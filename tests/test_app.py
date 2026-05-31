from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from renovate_vuln_report import Finding, ScanOutcome, run

from conftest import FailingCommentClient, FakeCommentClient, FakeScanner


def test_run_writes_step_summary_and_succeeds_when_vulnerabilities_are_found(
    tmp_path: Path,
    note: Callable[[dict[str, object]], str],
    docker_payload: Callable[..., dict[str, object]],
    pull_request_event: Callable[[str], dict[str, object]],
) -> None:
    event_path = tmp_path / "event.json"
    summary_path = tmp_path / "summary.md"
    event_path.write_text(json.dumps(pull_request_event(note(docker_payload()))))
    scanner = FakeScanner(
        {
            "ghcr.io/acme/app:1.1.0@sha256:bbb": ScanOutcome(
                findings=(
                    Finding(
                        vulnerability_id="CVE-2024-0001",
                        severity="High",
                        package_name="openssl",
                        installed_version="1.2.0",
                        fixed_versions=("1.2.3",),
                        epss=0.91,
                        kev=True,
                    ),
                )
            )
        }
    )

    exit_code = run(
        event_name="pull_request",
        event_path=event_path,
        summary_path=summary_path,
        scanner=scanner,
    )

    assert exit_code == 0
    assert scanner.scanned == ["ghcr.io/acme/app:1.1.0@sha256:bbb"]
    summary = summary_path.read_text()
    assert "# Image Update Vulnerability Report" in summary
    assert "ghcr.io/acme/app:1.1.0@sha256:bbb" in summary
    assert "[CVE-2024-0001](https://nvd.nist.gov/vuln/detail/CVE-2024-0001)" in summary
    assert "openssl" in summary
    assert "KEV" in summary
    assert "0.91" in summary


def test_run_succeeds_when_only_unsupported_entries_are_present(
    tmp_path: Path,
    note: Callable[[dict[str, object]], str],
    pull_request_event: Callable[[str], dict[str, object]],
) -> None:
    event_path = tmp_path / "event.json"
    summary_path = tmp_path / "summary.md"
    event_path.write_text(
        json.dumps(
            pull_request_event(
                note(
                    {
                        "depName": "lodash",
                        "packageName": "lodash",
                        "manager": "npm",
                        "datasource": "npm",
                        "updateType": "patch",
                        "currentValue": "1.0.0",
                        "newValue": "1.0.1",
                    }
                )
            )
        )
    )
    scanner = FakeScanner({})

    exit_code = run(
        event_name="pull_request",
        event_path=event_path,
        summary_path=summary_path,
        scanner=scanner,
    )

    assert exit_code == 0
    assert scanner.scanned == []
    summary = summary_path.read_text()
    assert "No supported Scan Targets were found" in summary
    assert "unsupported datasource: npm" in summary


def test_run_publishes_pull_request_comment_when_selected(
    tmp_path: Path,
    note: Callable[[dict[str, object]], str],
    docker_payload: Callable[..., dict[str, object]],
    pull_request_event: Callable[[str], dict[str, object]],
) -> None:
    event_path = tmp_path / "event.json"
    summary_path = tmp_path / "summary.md"
    event_path.write_text(json.dumps(pull_request_event(note(docker_payload()))))
    scanner = FakeScanner(
        {"ghcr.io/acme/app:1.1.0@sha256:bbb": ScanOutcome(findings=())}
    )
    comment_client = FakeCommentClient()

    exit_code = run(
        event_name="pull_request",
        event_path=event_path,
        summary_path=summary_path,
        scanner=scanner,
        report_surface="pr-comment",
        comment_client=comment_client,
    )

    assert exit_code == 0
    assert not summary_path.exists()
    assert len(comment_client.created) == 1
    repository, issue_number, body = comment_client.created[0]
    assert repository == "acme/widgets"
    assert issue_number == 17
    assert body.startswith("<!-- renovate-vuln-report:managed-comment:v1 -->")
    assert "# Image Update Vulnerability Report" in body
    assert "No Vulnerability Findings found" in body


def test_run_fails_when_selected_pull_request_comment_cannot_be_published(
    tmp_path: Path,
    note: Callable[[dict[str, object]], str],
    docker_payload: Callable[..., dict[str, object]],
    pull_request_event: Callable[[str], dict[str, object]],
) -> None:
    event_path = tmp_path / "event.json"
    summary_path = tmp_path / "summary.md"
    event_path.write_text(json.dumps(pull_request_event(note(docker_payload()))))
    scanner = FakeScanner(
        {"ghcr.io/acme/app:1.1.0@sha256:bbb": ScanOutcome(findings=())}
    )

    exit_code = run(
        event_name="pull_request",
        event_path=event_path,
        summary_path=summary_path,
        scanner=scanner,
        report_surface="pr-comment",
        comment_client=FailingCommentClient(),
    )

    assert exit_code == 1
    assert not summary_path.exists()


def test_run_fails_preconditions_before_scanning(
    tmp_path: Path,
    note: Callable[[dict[str, object]], str],
    docker_payload: Callable[..., dict[str, object]],
    pull_request_event: Callable[[str], dict[str, object]],
) -> None:
    event_path = tmp_path / "event.json"
    summary_path = tmp_path / "summary.md"
    event_path.write_text(json.dumps(pull_request_event(note(docker_payload()))))

    assert (
        run(
            event_name="push",
            event_path=event_path,
            summary_path=summary_path,
            scanner=FakeScanner({}),
        )
        == 1
    )

    event_path.write_text(json.dumps({"pull_request": {}}))
    assert (
        run(
            event_name="pull_request",
            event_path=event_path,
            summary_path=summary_path,
            scanner=FakeScanner({}),
        )
        == 1
    )

    event_path.write_text(json.dumps(pull_request_event("ordinary body")))
    assert (
        run(
            event_name="pull_request",
            event_path=event_path,
            summary_path=summary_path,
            scanner=FakeScanner({}),
        )
        == 1
    )

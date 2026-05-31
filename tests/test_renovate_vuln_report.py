import base64
import json
from pathlib import Path

import pytest

from renovate_vuln_report import (
    Finding,
    ImageUpdateEntry,
    MetadataError,
    NoMetadataNotesError,
    ScanFailure,
    ScanOutcome,
    UnsupportedUpdateEntry,
    collect_update_entries,
    findings_from_grype_json,
    run,
)


def note(payload: dict[str, object]) -> str:
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    return f"<!-- renovate:metadata={encoded} -->"


def docker_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "depName": "ghcr.io/acme/display-name",
        "packageName": "ghcr.io/acme/app",
        "manager": "dockerfile",
        "datasource": "docker",
        "updateType": "minor",
        "currentValue": "1.0.0",
        "newValue": "1.1.0",
        "currentDigest": "sha256:aaa",
        "newDigest": "sha256:bbb",
    }
    payload.update(overrides)
    return payload


def pull_request_event(body: str) -> dict[str, object]:
    return {"pull_request": {"body": body}}


class FakeScanner:
    def __init__(self, outcomes: dict[str, ScanOutcome | Exception]) -> None:
        self.outcomes = outcomes
        self.scanned: list[str] = []

    def scan(self, scan_target: str) -> ScanOutcome:
        self.scanned.append(scan_target)
        outcome = self.outcomes[scan_target]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_collect_update_entries_interprets_image_updates_and_skipped_entries() -> None:
    body = "\n".join(
        [
            note(docker_payload()),
            note(
                {
                    "depName": "lodash",
                    "packageName": "lodash",
                    "manager": "npm",
                    "datasource": "npm",
                    "updateType": "patch",
                    "currentValue": "1.0.0",
                    "newValue": "1.0.1",
                    "currentDigest": None,
                    "newDigest": None,
                }
            ),
        ]
    )

    image_entry, skipped_entry = collect_update_entries(body)

    assert isinstance(image_entry, ImageUpdateEntry)
    assert image_entry.repository == "ghcr.io/acme/app"
    assert image_entry.current_revision is not None
    assert image_entry.current_revision.reference == "ghcr.io/acme/app:1.0.0@sha256:aaa"
    assert image_entry.new_revision.reference == "ghcr.io/acme/app:1.1.0@sha256:bbb"

    assert isinstance(skipped_entry, UnsupportedUpdateEntry)
    assert skipped_entry.reason == "unsupported datasource: npm"


def test_collect_update_entries_uses_dep_name_when_package_name_is_absent() -> None:
    (entry,) = collect_update_entries(note(docker_payload(packageName=None)))

    assert isinstance(entry, ImageUpdateEntry)
    assert entry.repository == "ghcr.io/acme/display-name"


def test_collect_update_entries_rejects_missing_and_malformed_notes() -> None:
    with pytest.raises(NoMetadataNotesError):
        collect_update_entries("ordinary pull request body")

    with pytest.raises(MetadataError):
        collect_update_entries("<!-- renovate:metadata=not-base64 -->")

    encoded_list = base64.b64encode(b"[]").decode()
    with pytest.raises(MetadataError):
        collect_update_entries(f"<!-- renovate:metadata={encoded_list} -->")


def test_findings_from_grype_json_maps_package_fix_epss_and_kev() -> None:
    grype_json = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-0001",
                    "severity": "High",
                    "fix": {"versions": ["1.2.3"]},
                    "epss": [{"epss": 0.91}],
                    "knownExploited": [{"cve": "CVE-2024-0001"}],
                },
                "artifact": {"name": "openssl", "version": "1.2.0"},
            }
        ]
    }

    (finding,) = findings_from_grype_json(grype_json)

    assert finding == Finding(
        vulnerability_id="CVE-2024-0001",
        severity="High",
        package_name="openssl",
        installed_version="1.2.0",
        fixed_versions=("1.2.3",),
        epss=0.91,
        kev=True,
    )


def test_run_writes_step_summary_and_succeeds_when_vulnerabilities_are_found(
    tmp_path: Path,
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
    assert "CVE-2024-0001" in summary
    assert "openssl" in summary
    assert "KEV" in summary
    assert "0.91" in summary


def test_run_deduplicates_scan_targets_but_reports_shared_target(
    tmp_path: Path,
) -> None:
    event_path = tmp_path / "event.json"
    summary_path = tmp_path / "summary.md"
    body = "\n".join(
        [note(docker_payload()), note(docker_payload(depName="ghcr.io/acme/app-copy"))]
    )
    event_path.write_text(json.dumps(pull_request_event(body)))
    scanner = FakeScanner(
        {"ghcr.io/acme/app:1.1.0@sha256:bbb": ScanOutcome(findings=())}
    )

    exit_code = run(
        event_name="pull_request",
        event_path=event_path,
        summary_path=summary_path,
        scanner=scanner,
    )

    assert exit_code == 0
    assert scanner.scanned == ["ghcr.io/acme/app:1.1.0@sha256:bbb"]
    assert "Shared by 2 Image Update Entries" in summary_path.read_text()


def test_run_continues_and_fails_after_partial_report_when_a_scan_fails(
    tmp_path: Path,
) -> None:
    event_path = tmp_path / "event.json"
    summary_path = tmp_path / "summary.md"
    body = "\n".join(
        [
            note(docker_payload(packageName="ghcr.io/acme/ok", newDigest="sha256:ok")),
            note(
                docker_payload(
                    packageName="ghcr.io/acme/private", newDigest="sha256:private"
                )
            ),
        ]
    )
    event_path.write_text(json.dumps(pull_request_event(body)))
    scanner = FakeScanner(
        {
            "ghcr.io/acme/ok:1.1.0@sha256:ok": ScanOutcome(
                findings=(
                    Finding(
                        vulnerability_id="CVE-2024-0002",
                        severity="Medium",
                        package_name="zlib",
                        installed_version="1.0",
                    ),
                )
            ),
            "ghcr.io/acme/private:1.1.0@sha256:private": ScanFailure(
                public_reason="registry authentication failed",
                detail="token=secret should stay in logs",
            ),
        }
    )

    exit_code = run(
        event_name="pull_request",
        event_path=event_path,
        summary_path=summary_path,
        scanner=scanner,
    )

    assert exit_code == 1
    assert scanner.scanned == [
        "ghcr.io/acme/ok:1.1.0@sha256:ok",
        "ghcr.io/acme/private:1.1.0@sha256:private",
    ]
    summary = summary_path.read_text()
    assert "CVE-2024-0002" in summary
    assert "registry authentication failed" in summary
    assert "token=secret" not in summary


def test_run_succeeds_when_only_unsupported_entries_are_present(tmp_path: Path) -> None:
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


def test_run_fails_preconditions_before_scanning(tmp_path: Path) -> None:
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

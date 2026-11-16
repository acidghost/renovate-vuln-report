from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path

import pytest

from renovate_vuln_report.cli import main


@pytest.mark.parametrize(
    ("args", "env_level", "runner_debug", "expected_level"),
    [
        ([], None, None, logging.INFO),
        ([], "warning", None, logging.WARNING),
        (["--log-level", "INFO"], "error", None, logging.INFO),
        (["--log-level", "error"], "debug", None, logging.ERROR),
        ([], None, "1", logging.DEBUG),
        ([], "", "1", logging.DEBUG),
        ([], None, "0", logging.INFO),
        ([], "info", "1", logging.INFO),
        (["--log-level", "warning"], "debug", "1", logging.WARNING),
    ],
)
def test_cli_configures_log_level(
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
    env_level: str | None,
    runner_debug: str | None,
    expected_level: int,
) -> None:
    monkeypatch.setattr("sys.argv", ["renovate-vuln-report", *args])
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    for key, value in {
        "RENOVATE_VULN_REPORT_LOG_LEVEL": env_level,
        "RUNNER_DEBUG": runner_debug,
    }.items():
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)

    logger = logging.getLogger("renovate_vuln_report")
    original_level = logger.level
    try:
        # Logging is configured before event validation; stop there without
        # involving a scanner or report publishing.
        with pytest.raises(SystemExit) as exit_info:
            main()
        assert exit_info.value.code == 1
        assert logger.level == expected_level
    finally:
        logger.setLevel(original_level)


@pytest.mark.parametrize(
    ("args", "env_level"),
    [([], "verbose"), (["--log-level", "verbose"], None)],
)
def test_cli_rejects_invalid_log_level(
    monkeypatch: pytest.MonkeyPatch, args: list[str], env_level: str | None
) -> None:
    monkeypatch.setattr("sys.argv", ["renovate-vuln-report", *args])
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    if env_level is None:
        monkeypatch.delenv("RENOVATE_VULN_REPORT_LOG_LEVEL", raising=False)
    else:
        monkeypatch.setenv("RENOVATE_VULN_REPORT_LOG_LEVEL", env_level)
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 2


@pytest.mark.parametrize(
    ("payloads", "needs_scanning"),
    [
        ([{"datasource": "github-releases", "depName": "anchore/grype"}], False),
        ([{"datasource": "docker", "depName": "alpine", "newValue": "3.23"}], True),
        ([{"datasource": "docker", "depName": "alpine"}], False),
        ([{"datasource": "docker", "newValue": "3.23"}], False),
        (
            [
                {"datasource": "github-releases"},
                {
                    "datasource": "docker",
                    "depName": "alpine",
                    "newDigest": "sha256:abc",
                },
            ],
            True,
        ),
    ],
)
def test_preflight_checks_metadata_without_grype_or_publishing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    note: Callable[[dict[str, object]], str],
    pull_request_event: Callable[[str], dict[str, object]],
    payloads: list[dict[str, object]],
    needs_scanning: bool,
) -> None:
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(pull_request_event("\n".join(note(payload) for payload in payloads)))
    )
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    monkeypatch.setattr(
        "sys.argv",
        ["renovate-vuln-report", "--preflight", "--report-surface", "pr-comment"],
    )
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.delenv("FORGE_TOKEN", raising=False)
    monkeypatch.setenv("PATH", "")

    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 0
    assert output.read_text() == f"needs-scanning={str(needs_scanning).lower()}\n"
    assert not summary.exists()


@pytest.mark.parametrize("body", ["<!-- renovate:metadata=bad -->", "not metadata"])
def test_preflight_defers_metadata_errors_to_normal_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    pull_request_event: Callable[[str], dict[str, object]],
    body: str,
) -> None:
    event = tmp_path / "event.json"
    event.write_text(json.dumps(pull_request_event(body)))
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    monkeypatch.setattr("sys.argv", ["renovate-vuln-report", "--preflight"])
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("RENOVATE_VULN_REPORT_SURFACE", "summary")
    monkeypatch.setenv("PATH", "")

    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 0
    assert output.read_text() == "needs-scanning=false\n"

    monkeypatch.setattr("sys.argv", ["renovate-vuln-report"])
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 1
    assert "Failed:" in summary.read_text()

from __future__ import annotations

import logging

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

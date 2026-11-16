"""Exercise database preparation and check the shared cache contract."""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REPORT_ACTION = ROOT / "action.yml"
WARMUP_ACTION = ROOT / "grype-db-cache" / "action.yml"
CACHE_KEY_SCRIPT = ROOT / "grype-db-cache" / "cache_key.py"


def step(action: Path, name: str) -> dict[str, Any]:
    document = yaml.safe_load(action.read_text())
    return next(
        candidate
        for candidate in document["runs"]["steps"]
        if candidate["name"] == name
    )


def shell(script: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        env=os.environ | env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def commands(tmp_path: Path) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    scripts = {
        "grype": """#!/bin/sh
case "$*" in
  'version --output json')
    printf '{"version":"%s","supportedDbSchema":%s}\\n' "$FAKE_GRYPE_VERSION" "$FAKE_GRYPE_SCHEMA"
    ;;
  'db update')
    printf '%s\\n' "$GRYPE_DB_CACHE_DIR" >> "$GRYPE_UPDATE_LOG"
    exit "${GRYPE_UPDATE_EXIT_CODE:-0}"
    ;;
  *) exit 1 ;;
esac
""",
    }
    for name, content in scripts.items():
        executable = bin_dir / name
        executable.write_text(content)
        executable.chmod(0o755)
    return {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "FAKE_GRYPE_VERSION": "0.120.1",
        "FAKE_GRYPE_SCHEMA": "6",
    }


def test_database_cache_contract_matches_between_actions(
    tmp_path: Path, commands: dict[str, str]
) -> None:
    prefix = "renovate-vuln-report-grype-db-v3-Linux-X64-schema-6-"
    for index, action in enumerate((REPORT_ACTION, WARMUP_ACTION)):
        output = tmp_path / f"{index}.output"
        prepare = step(action, "Prepare Grype database cache key")
        assert prepare["shell"] == "sh"
        before = datetime.now(UTC).date().isoformat()
        result = subprocess.run(
            ["sh", "-e", "-c", prepare["run"]],
            env=os.environ
            | commands
            | {
                "GITHUB_ACTION_PATH": str(action.parent),
                "GITHUB_OUTPUT": str(output),
            },
            cwd=tmp_path,  # The consumer checkout is not the action directory.
            capture_output=True,
            text=True,
            check=False,
        )
        after = datetime.now(UTC).date().isoformat()
        assert result.returncode == 0, result.stderr
        lines = output.read_text().splitlines()
        assert lines[0] == f"prefix={prefix}"
        assert lines[1] in {f"key={prefix}{date}" for date in (before, after)}
    report_restore = step(REPORT_ACTION, "Restore Grype database")
    warm_restore = step(WARMUP_ACTION, "Restore Grype database")
    for field in ("path", "key", "restore-keys"):
        assert report_restore["with"][field] == warm_restore["with"][field]
    assert report_restore["uses"] == warm_restore["uses"]
    # Save must use exactly the same archive path/key as restore.
    warm_save = step(WARMUP_ACTION, "Save Grype database")
    for field in ("path", "key"):
        assert warm_save["with"][field] == warm_restore["with"][field]


@pytest.mark.parametrize(
    ("event", "ref", "branch", "allowed"),
    [
        ("schedule", "refs/heads/main", "main", True),
        ("workflow_dispatch", "refs/heads/trunk", "trunk", True),
        ("push", "refs/heads/main", "main", True),
        ("workflow_dispatch", "refs/heads/feature", "main", False),
        ("pull_request", "refs/pull/17/merge", "main", False),
        ("pull_request_target", "refs/heads/main", "main", False),
        ("schedule", "refs/heads/main", "", True),
        ("schedule", "refs/heads/releases/stable", "", True),
        ("workflow_dispatch", "refs/heads/main", "", False),
        ("push", "refs/heads/main", "", False),
        ("workflow_dispatch", "refs/tags/main", "main", False),
        ("pull_request_target", "refs/heads/main", "", False),
    ],
)
def test_warmup_requires_default_branch_non_pr_run(
    event: str, ref: str, branch: str, allowed: bool
) -> None:
    result = shell(
        step(WARMUP_ACTION, "Require a default-branch non-PR run")["run"],
        {"GITHUB_EVENT_NAME": event, "GITHUB_REF": ref, "DEFAULT_BRANCH": branch},
    )
    assert (result.returncode == 0) == allowed
    if not allowed:
        assert "default branch, outside a PR" in result.stderr


def test_report_action_passes_optional_log_level_without_shell_interpolation() -> None:
    document = yaml.safe_load(REPORT_ACTION.read_text())
    assert document["inputs"]["log-level"]["default"] == ""
    report = step(REPORT_ACTION, "Generate Renovate vulnerability report")
    assert report["env"]["RENOVATE_VULN_REPORT_LOG_LEVEL"] == "${{ inputs.log-level }}"
    assert "${{ inputs.log-level }}" not in report["run"]


def test_database_key_uses_schema_not_scanner_version(
    tmp_path: Path, commands: dict[str, str]
) -> None:
    outputs = []
    for index, (version, schema) in enumerate(
        [("0.120.1", "6"), ("0.121.2", "6"), ("0.200.0", "7")]
    ):
        output = tmp_path / f"{index}.output"
        result = subprocess.run(
            [sys.executable, str(CACHE_KEY_SCRIPT)],
            env=os.environ
            | commands
            | {
                "GITHUB_OUTPUT": str(output),
                "FAKE_GRYPE_VERSION": version,
                "FAKE_GRYPE_SCHEMA": schema,
            },
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        outputs.append(output.read_text().splitlines()[0])
    assert outputs[0] == outputs[1]
    assert outputs[0] != outputs[2]
    assert "schema-7-" in outputs[2]


@pytest.mark.parametrize("schema", ["null", '"unknown"', "0", "true", "6.5"])
def test_database_key_rejects_unknown_schema(
    schema: str, tmp_path: Path, commands: dict[str, str]
) -> None:
    output = tmp_path / "output"
    result = subprocess.run(
        [sys.executable, str(CACHE_KEY_SCRIPT)],
        env=os.environ
        | commands
        | {
            "GITHUB_OUTPUT": str(output),
            "FAKE_GRYPE_SCHEMA": schema,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "positive integer database schema" in result.stderr
    assert not output.exists()


@pytest.mark.parametrize("restored_key", ["", "today-schema-6", "older-schema-6"])
def test_report_downloads_database_only_on_complete_cache_miss(
    restored_key: str, tmp_path: Path, commands: dict[str, str]
) -> None:
    update_log = tmp_path / "updates"
    database = tmp_path / "database"
    result = shell(
        step(REPORT_ACTION, "Prepare Grype database")["run"],
        commands
        | {
            "RESTORED_KEY": restored_key,
            "GRYPE_DB_CACHE_DIR": str(database),
            "GRYPE_UPDATE_LOG": str(update_log),
        },
    )
    assert result.returncode == 0, result.stderr
    if restored_key:
        assert not update_log.exists()
    else:
        assert update_log.read_text() == f"{database}\n"


def test_report_database_download_failure_is_fatal(
    tmp_path: Path, commands: dict[str, str]
) -> None:
    result = shell(
        step(REPORT_ACTION, "Prepare Grype database")["run"],
        commands
        | {
            "RESTORED_KEY": "",
            "GRYPE_DB_CACHE_DIR": str(tmp_path / "database"),
            "GRYPE_UPDATE_LOG": str(tmp_path / "updates"),
            "GRYPE_UPDATE_EXIT_CODE": "42",
        },
    )
    assert result.returncode == 42


def test_report_database_wiring_and_no_database_publication() -> None:
    document = yaml.safe_load(REPORT_ACTION.read_text())
    steps = document["runs"]["steps"]
    names = [candidate["name"] for candidate in steps]
    assert names.index("Check for supported image updates") < names.index(
        "Prepare Grype database cache key"
    )
    assert names.index("Restore Grype database") < names.index("Prepare Grype database")
    assert names.index("Prepare Grype database") < names.index(
        "Generate Renovate vulnerability report"
    )
    restore = step(REPORT_ACTION, "Restore Grype database")
    assert restore["with"].get("fail-on-cache-miss", "false") == "false"
    prepare = step(REPORT_ACTION, "Prepare Grype database")
    assert (
        prepare["env"]["RESTORED_KEY"]
        == "${{ steps.grype-db-cache.outputs.cache-matched-key }}"
    )
    assert prepare["env"]["GRYPE_DB_CACHE_DIR"] == restore["with"]["path"]
    assert (
        step(REPORT_ACTION, "Generate Renovate vulnerability report")["env"][
            "GRYPE_DB_AUTO_UPDATE"
        ]
        == "false"
    )
    saves = [
        candidate
        for candidate in steps
        if "actions/cache/save@" in candidate.get("uses", "")
    ]
    assert all(
        restore["with"]["path"] not in candidate["with"]["path"] for candidate in saves
    )

"""Check the shared database cache contract and execute the warmup guard."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REPORT_ACTION = ROOT / "action.yml"
WARMUP_ACTION = ROOT / "grype-db-cache" / "action.yml"


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
        "grype": '#!/bin/sh\n[ "$1" = version ] || exit 1\nprintf \'Version: %s\\n\' "$FAKE_GRYPE_VERSION"\n',
        "date": "#!/bin/sh\n[ \"$*\" = '-u +%Y-%m-%d' ] || exit 1\necho 2026-10-18\n",
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
    }


def test_database_cache_contract_matches_between_actions(
    tmp_path: Path, commands: dict[str, str]
) -> None:
    outputs = []
    for index, action in enumerate((REPORT_ACTION, WARMUP_ACTION)):
        output = tmp_path / f"{index}.output"
        result = shell(
            step(action, "Prepare Grype database cache key")["run"],
            commands | {"GITHUB_OUTPUT": str(output)},
        )
        assert result.returncode == 0, result.stderr
        outputs.append(output.read_text())
    assert (
        outputs[0]
        == outputs[1]
        == (
            "prefix=renovate-vuln-report-grype-db-v2-Linux-X64-0.120.1-\n"
            "key=renovate-vuln-report-grype-db-v2-Linux-X64-0.120.1-2026-10-18\n"
        )
    )
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
        ("schedule", "refs/heads/main", "", False),
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

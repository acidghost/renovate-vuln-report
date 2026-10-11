from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from renovate_vuln_report import ScanFailure, UnsupportedScanTarget, run
from renovate_vuln_report.cli import main
from renovate_vuln_report.oci import FetchedManifest
from renovate_vuln_report.scan import GrypeScanner

DIGEST = "sha256:" + "a" * 64
TARGET = f"ghcr.io/acme/app:1.1.0@{DIGEST}"
DOCUMENT = {
    "matches": [
        {
            "vulnerability": {"id": "CVE-2024-0001", "severity": "High"},
            "artifact": {"name": "openssl", "version": "1.2.0"},
        }
    ],
    "descriptor": {"configuration": {"password": "secret"}},
}


class ManifestStub:
    def __init__(self) -> None:
        self.manifest: FetchedManifest | None = FetchedManifest(
            {"mediaType": "application/vnd.oci.image.index.v1+json"}, DIGEST
        )

    def fetch(self, reference: str) -> FetchedManifest | None:
        return self.manifest


class FakeGrype:
    def __init__(self, database: Path) -> None:
        self.database = database
        self.version = "1.0.0"
        self.config = "platform: linux/amd64"
        self.valid = True
        self.document: Any = DOCUMENT
        self.returncode = 0
        self.fail_targets: set[str] = set()
        self.calls: list[list[str]] = []
        self.scans: list[str] = []

    def __call__(
        self, command: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        args = command[1:]
        code = 0
        if args == ["version", "-o", "json"]:
            output = json.dumps({"version": self.version})
        elif args == ["config", "--load"]:
            output = self.config
        elif args == ["db", "status", "-o", "json"]:
            output = json.dumps({"path": str(self.database), "valid": self.valid})
            code = 0 if self.valid else 1
        else:
            assert args[:2] == ["-o", "json"]
            self.scans.append(args[-1])
            output = json.dumps(self.document)
            code = 1 if args[-1] in self.fail_targets else self.returncode
        if code and kwargs.get("check"):
            raise subprocess.CalledProcessError(code, command)
        return subprocess.CompletedProcess(command, code, output, "scan failed")


@pytest.fixture
def grype(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeGrype:
    database = tmp_path / "vulnerability.db"
    database.write_bytes(b"database snapshot 1")
    fake = FakeGrype(database)
    monkeypatch.setattr("renovate_vuln_report.scan.subprocess.run", fake)
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", "false")
    return fake


def scanner(tmp_path: Path, manifest: ManifestStub | None = None) -> GrypeScanner:
    return GrypeScanner(
        manifest_fetcher=manifest or ManifestStub(), cache_dir=tmp_path / "scans"
    )


def test_pr_sync_reuses_scan_and_still_publishes_report(
    tmp_path: Path,
    grype: FakeGrype,
    note: Callable[[dict[str, object]], str],
    docker_payload: Callable[..., dict[str, object]],
    pull_request_event: Callable[[str], dict[str, object]],
) -> None:
    event_path = tmp_path / "event.json"
    event = pull_request_event(note(docker_payload(newDigest=DIGEST)))
    summaries = []
    for commit in ("before-sync", "after-sync"):
        event["after"] = commit
        event_path.write_text(json.dumps(event))
        summary_path = tmp_path / f"{commit}.md"
        assert (
            run(
                event_name="pull_request",
                event_path=event_path,
                summary_path=summary_path,
                scanner=scanner(tmp_path),
            )
            == 0
        )
        summaries.append(summary_path.read_text())

    assert grype.scans == [f"registry:ghcr.io/acme/app@{DIGEST}"]
    assert summaries[0] == summaries[1]
    assert "CVE-2024-0001" in summaries[1]
    (cached,) = (tmp_path / "scans").rglob("*.json")
    assert "secret" not in cached.read_text()


@pytest.mark.parametrize("change", ["image", "database", "version", "config", "env"])
def test_changed_scan_inputs_trigger_new_scan(
    tmp_path: Path, grype: FakeGrype, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    scanner(tmp_path).scan(TARGET)
    target = TARGET
    if change == "image":
        target = TARGET.replace("a" * 64, "b" * 64)
    elif change == "database":
        grype.database.write_bytes(b"database snapshot 2")
    elif change == "version":
        grype.version = "2.0.0"
    elif change == "config":
        grype.config = "platform: linux/arm64"
    else:
        monkeypatch.setenv("SYFT_SEARCH_SCOPE", "all-layers")

    scanner(tmp_path).scan(target)
    assert len(grype.scans) == 2


def test_tag_only_targets_are_resolved_pinned_and_invalidated_when_moved(
    tmp_path: Path, grype: FakeGrype
) -> None:
    manifest = ManifestStub()
    scanner(tmp_path, manifest).scan("ghcr.io:5000/acme/app:latest")
    scanner(tmp_path, manifest).scan("ghcr.io:5000/acme/app:latest")
    assert manifest.manifest is not None
    manifest.manifest = FetchedManifest(
        manifest.manifest.document, "sha256:" + "b" * 64
    )
    scanner(tmp_path, manifest).scan("ghcr.io:5000/acme/app:latest")
    assert grype.scans == [
        f"registry:ghcr.io:5000/acme/app@{DIGEST}",
        "registry:ghcr.io:5000/acme/app@sha256:" + "b" * 64,
    ]


def test_pinned_target_can_use_cache_when_manifest_fetch_fails(
    tmp_path: Path, grype: FakeGrype
) -> None:
    manifest = ManifestStub()
    manifest.manifest = None
    scanner(tmp_path, manifest).scan(TARGET)
    scanner(tmp_path, manifest).scan(TARGET)
    assert len(grype.scans) == 1


@pytest.mark.parametrize("manifest_available", [False, True])
def test_unresolved_tag_is_not_cached(
    tmp_path: Path, grype: FakeGrype, manifest_available: bool
) -> None:
    manifest = ManifestStub()
    manifest.manifest = (
        FetchedManifest({"mediaType": "application/vnd.oci.image.index.v1+json"})
        if manifest_available
        else None
    )
    for _ in range(2):
        scanner(tmp_path, manifest).scan("ghcr.io/acme/app:latest")
    assert len(grype.scans) == 2
    assert not (tmp_path / "scans").exists()


def test_same_digest_with_a_different_tag_reuses_scan(
    tmp_path: Path, grype: FakeGrype
) -> None:
    scanner(tmp_path).scan(TARGET)
    scanner(tmp_path).scan(TARGET.replace(":1.1.0@", ":stable@"))
    assert len(grype.scans) == 1


@pytest.mark.parametrize("document", [None, {"matches": []}])
def test_successful_scans_including_empty_findings_are_cached(
    tmp_path: Path, grype: FakeGrype, document: Any
) -> None:
    if document is not None:
        grype.document = document
    first = scanner(tmp_path).scan(TARGET)
    second_scanner = scanner(tmp_path)
    assert second_scanner.scan(TARGET) == first
    assert not second_scanner.cache_updated
    assert len(grype.scans) == 1


def test_scan_failures_are_not_cached(tmp_path: Path, grype: FakeGrype) -> None:
    grype.returncode = 1
    for _ in range(2):
        with pytest.raises(ScanFailure):
            scanner(tmp_path).scan(TARGET)
    assert len(grype.scans) == 2
    assert not (tmp_path / "scans").exists()


@pytest.mark.parametrize("corrupt", ["not json", "null", "{}", '{"matches": [null]}'])
def test_corrupt_cache_entries_are_rescanned(
    tmp_path: Path, grype: FakeGrype, corrupt: str
) -> None:
    first = scanner(tmp_path).scan(TARGET)
    (cached,) = (tmp_path / "scans").rglob("*.json")
    cached.write_text(corrupt)
    assert scanner(tmp_path).scan(TARGET) == first
    assert len(grype.scans) == 2


def test_cache_io_failure_does_not_fail_scan(tmp_path: Path, grype: FakeGrype) -> None:
    (tmp_path / "scans").write_text("not a directory")
    assert scanner(tmp_path).scan(TARGET).findings
    assert len(grype.scans) == 1


@pytest.mark.parametrize("auto_update", ["true", ""])
def test_cache_bypassed_when_database_is_not_frozen(
    tmp_path: Path, grype: FakeGrype, monkeypatch: pytest.MonkeyPatch, auto_update: str
) -> None:
    monkeypatch.setenv("GRYPE_DB_AUTO_UPDATE", auto_update)
    for _ in range(2):
        scanner(tmp_path).scan(TARGET)
    assert len(grype.scans) == 2
    assert len(grype.calls) == 2


def test_invalid_database_cannot_produce_cache_hit(
    tmp_path: Path, grype: FakeGrype
) -> None:
    scanner(tmp_path).scan(TARGET)
    grype.valid = False
    scanner(tmp_path).scan(TARGET)
    assert len(grype.scans) == 2


def test_unsupported_target_is_not_cached(tmp_path: Path, grype: FakeGrype) -> None:
    manifest = ManifestStub()
    manifest.manifest = FetchedManifest(
        {"config": {"mediaType": "application/vnd.cncf.helm.config.v1+json"}}, DIGEST
    )
    with pytest.raises(UnsupportedScanTarget):
        scanner(tmp_path, manifest).scan(TARGET)
    assert grype.calls == []


@pytest.mark.parametrize("partial_failure", [False, True])
def test_cli_signals_cache_updates_only_on_misses(
    tmp_path: Path,
    grype: FakeGrype,
    monkeypatch: pytest.MonkeyPatch,
    note: Callable[[dict[str, object]], str],
    docker_payload: Callable[..., dict[str, object]],
    pull_request_event: Callable[[str], dict[str, object]],
    partial_failure: bool,
) -> None:
    event_path = tmp_path / "event.json"
    body = note(docker_payload(newDigest=DIGEST))
    if partial_failure:
        body += note(
            docker_payload(packageName="ghcr.io/acme/private", newDigest=DIGEST)
        )
        grype.fail_targets.add(f"registry:ghcr.io/acme/private@{DIGEST}")
    event_path.write_text(json.dumps(pull_request_event(body)))
    output_path = tmp_path / "output"
    monkeypatch.setattr("sys.argv", ["renovate-vuln-report"])
    monkeypatch.setattr(
        "renovate_vuln_report.scan.make_default_manifest_fetcher", ManifestStub
    )
    for key, value in {
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
        "GITHUB_OUTPUT": str(output_path),
        "RENOVATE_VULN_REPORT_SCAN_CACHE_DIR": str(tmp_path / "scans"),
    }.items():
        monkeypatch.setenv(key, value)

    for expected_output in ("scan-cache-updated=true\n", ""):
        output_path.write_text("")
        with pytest.raises(SystemExit) as info:
            main()
        assert info.value.code == (1 if partial_failure else 0)
        assert output_path.read_text() == expected_output
    assert grype.scans.count(f"registry:ghcr.io/acme/app@{DIGEST}") == 1
    if partial_failure:
        assert grype.scans.count(f"registry:ghcr.io/acme/private@{DIGEST}") == 2

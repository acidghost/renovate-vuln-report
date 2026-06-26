from __future__ import annotations

import subprocess
from typing import Any

import pytest

from renovate_vuln_report import (
    Finding,
    ScanFailure,
    ScanOutcome,
    UnsupportedScanTarget,
    findings_from_grype_json,
)
from renovate_vuln_report.oci import OrasManifestFetcher
from renovate_vuln_report.scan import GrypeScanner


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


HELM_CHART_MANIFEST = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {
        "mediaType": "application/vnd.cncf.helm.config.v1+json",
        "digest": "sha256:1111",
        "size": 117,
    },
    "layers": [
        {
            "mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip",
            "digest": "sha256:2222",
            "size": 4096,
        }
    ],
}

CONTAINER_IMAGE_MANIFEST = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": "sha256:3333",
        "size": 7023,
    },
    "layers": [
        {
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": "sha256:4444",
            "size": 31337,
        }
    ],
}

HELM_CHART_OCI_STDERR = (
    "[0062] ERROR failed to catalog: errors occurred attempting to resolve "
    "'ghcr.io/danny-avila/librechat-chart/librechat:2.0.7@sha256:abc':\n"
    "  - oci-registry: unsupported layer media type(s): layer 0: "
    "application/vnd.cncf.helm.chart.content.v1.tar+gzip\n"
    "  - oci-model: not an OCI model artifact (config media type: "
    "application/vnd.cncf.helm.config.v1+json)\n"
)


class RecordingRun:
    """A subprocess.run double that records whether grype was invoked."""

    def __init__(self, outcome: subprocess.CompletedProcess[str]) -> None:
        self._outcome = outcome
        self.calls: list[list[str]] = []

    def __call__(
        self, command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        return self._outcome


class ManifestFetcherStub:
    def __init__(self, manifest: dict[str, Any] | None) -> None:
        self._manifest = manifest

    def fetch(self, reference: str) -> dict[str, Any] | None:  # noqa: ARG002
        return self._manifest


def _completed(
    stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["grype"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_manifest_classifier_skips_helm_chart_without_invoking_grype(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = RecordingRun(_completed(stderr="should not run", returncode=1))
    monkeypatch.setattr("renovate_vuln_report.scan.subprocess.run", runner)

    with pytest.raises(UnsupportedScanTarget) as info:
        GrypeScanner(manifest_fetcher=ManifestFetcherStub(HELM_CHART_MANIFEST)).scan(
            "ghcr.io/danny-avila/librechat-chart/librechat:2.0.7"
        )

    assert "Helm chart" in info.value.public_reason
    assert runner.calls == []  # grype never ran


def test_manifest_classifier_proceeds_to_grype_for_container_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = RecordingRun(_completed(stdout='{"matches": []}'))
    monkeypatch.setattr("renovate_vuln_report.scan.subprocess.run", runner)

    outcome = GrypeScanner(
        manifest_fetcher=ManifestFetcherStub(CONTAINER_IMAGE_MANIFEST)
    ).scan("ghcr.io/acme/app:1.1.0")

    assert outcome == ScanOutcome(findings=())
    assert len(runner.calls) == 1
    assert runner.calls[0][-1] == "registry:ghcr.io/acme/app:1.1.0"


def test_manifest_fetch_failure_still_proceeds_to_grype(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # When the manifest cannot be fetched (unreachable/private registry),
    # classification is skipped and the target is still scanned.
    runner = RecordingRun(_completed(stdout='{"matches": []}'))
    monkeypatch.setattr("renovate_vuln_report.scan.subprocess.run", runner)

    outcome = GrypeScanner(manifest_fetcher=ManifestFetcherStub(None)).scan(
        "ghcr.io/acme/app:1.1.0"
    )

    assert outcome == ScanOutcome(findings=())
    assert len(runner.calls) == 1


def test_manifest_fetch_failure_surfaces_grype_failures_plainly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With the stderr backstop removed, a grype failure when the manifest could
    # not be fetched is a plain ScanFailure -- even for the Helm-chart stderr
    # that the backstop used to reinterpret. Non-image detection now relies
    # solely on the manifest classifier.
    runner = RecordingRun(_completed(stderr=HELM_CHART_OCI_STDERR, returncode=1))
    monkeypatch.setattr("renovate_vuln_report.scan.subprocess.run", runner)

    with pytest.raises(ScanFailure):
        GrypeScanner(manifest_fetcher=ManifestFetcherStub(None)).scan(
            "ghcr.io/acme/chart:2.0.7"
        )

    assert len(runner.calls) == 1


def test_grype_still_raises_scan_failure_for_other_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from renovate_vuln_report.oci import NullManifestFetcher

    monkeypatch.setattr(
        "renovate_vuln_report.scan.subprocess.run",
        RecordingRun(
            _completed(
                stderr="1 error occurred:\n\t* registry authentication failed",
                returncode=1,
            )
        ),
    )

    with pytest.raises(ScanFailure):
        GrypeScanner(manifest_fetcher=NullManifestFetcher()).scan(
            "ghcr.io/acme/private:1.0.0"
        )


def test_oras_manifest_fetcher_returns_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Registry:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get_manifest(self, reference: str) -> dict[str, Any]:
            assert reference == "ghcr.io/acme/chart:2.0.7"
            return HELM_CHART_MANIFEST

    monkeypatch.setattr("oras.provider.Registry", _Registry)

    assert (
        OrasManifestFetcher().fetch("ghcr.io/acme/chart:2.0.7") == HELM_CHART_MANIFEST
    )


def test_oras_manifest_fetcher_returns_none_when_registry_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Registry:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get_manifest(self, reference: str) -> dict[str, Any]:
            raise ValueError("Issue retrieving manifest: not found")

    monkeypatch.setattr("oras.provider.Registry", _Registry)

    assert OrasManifestFetcher().fetch("ghcr.io/acme/missing:1.0.0") is None


def test_oras_manifest_fetcher_is_bounded_by_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time

    class _SlowRegistry:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get_manifest(self, reference: str) -> dict[str, Any]:
            time.sleep(2.0)  # noqa: ARG002 -- simulates a hung registry
            return HELM_CHART_MANIFEST

    monkeypatch.setattr("oras.provider.Registry", _SlowRegistry)

    start = time.monotonic()
    result = OrasManifestFetcher(timeout_seconds=0.1).fetch("ghcr.io/acme/slow:1.0.0")
    elapsed = time.monotonic() - start

    assert result is None
    assert elapsed < 1.0

from __future__ import annotations

from renovate_vuln_report import (
    Finding,
    ImageRevision,
    ImageUpdateEntry,
    ScanFailure,
    ScanOutcome,
    UnsupportedScanTarget,
    UnsupportedUpdateEntry,
    build_report,
    render_step_summary,
)

from conftest import FakeScanner


def image_entry(repository: str, digest: str = "sha256:bbb") -> ImageUpdateEntry:
    return ImageUpdateEntry(
        repository=repository,
        new_revision=ImageRevision(repository=repository, tag="1.1.0", digest=digest),
    )


def test_build_report_deduplicates_scan_targets_and_reports_skipped_entries() -> None:
    scanner = FakeScanner(
        {"ghcr.io/acme/app:1.1.0@sha256:bbb": ScanOutcome(findings=())}
    )

    report = build_report(
        entries=(
            image_entry("ghcr.io/acme/app"),
            image_entry("ghcr.io/acme/app"),
            UnsupportedUpdateEntry(
                reason="unsupported datasource: npm", datasource="npm"
            ),
        ),
        scanner=scanner,
    )

    assert scanner.scanned == ["ghcr.io/acme/app:1.1.0@sha256:bbb"]
    assert report.target_reports[0].update_entry_count == 2
    assert report.skipped_entries[0].reason == "unsupported datasource: npm"

    summary = render_step_summary(report)
    assert "Shared by 2 Image Update Entries" in summary
    assert "unsupported datasource: npm" in summary


def test_build_report_continues_after_partial_scan_failure() -> None:
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

    report = build_report(
        entries=(
            image_entry("ghcr.io/acme/ok", "sha256:ok"),
            image_entry("ghcr.io/acme/private", "sha256:private"),
        ),
        scanner=scanner,
    )

    assert report.failed is True
    summary = render_step_summary(report)
    assert "CVE-2024-0002" in summary
    assert "registry authentication failed" in summary
    assert "token=secret" not in summary


def test_render_step_summary_links_vulnerability_findings() -> None:
    report = build_report(
        entries=(image_entry("ghcr.io/acme/app"),),
        scanner=FakeScanner(
            {
                "ghcr.io/acme/app:1.1.0@sha256:bbb": ScanOutcome(
                    findings=(
                        Finding(
                            vulnerability_id="GHSA-p436-gjf2-799p",
                            severity="High",
                            package_name="openssl",
                            installed_version="1.2.0",
                        ),
                    )
                )
            }
        ),
    )

    assert (
        "[GHSA-p436-gjf2-799p](https://github.com/advisories/GHSA-p436-gjf2-799p)"
        in render_step_summary(report)
    )


def test_build_report_treats_non_image_scan_target_as_skipped() -> None:
    scanner = FakeScanner(
        {
            "ghcr.io/acme/chart:1.1.0@sha256:helm": UnsupportedScanTarget(
                public_reason=(
                    "not a scannable container image: OCI artifact could not be "
                    "cataloged (for example a Helm chart stored as OCI)"
                ),
                detail="oci-model: not an OCI model artifact",
            ),
            "ghcr.io/acme/app:1.1.0@sha256:bbb": ScanOutcome(findings=()),
        }
    )

    report = build_report(
        entries=(
            image_entry("ghcr.io/acme/chart", "sha256:helm"),
            image_entry("ghcr.io/acme/app"),
        ),
        scanner=scanner,
    )

    assert report.failed is False
    assert [tr.scan_target for tr in report.target_reports] == [
        "ghcr.io/acme/app:1.1.0@sha256:bbb"
    ]
    assert len(report.skipped_entries) == 1
    skipped = report.skipped_entries[0]
    assert skipped.package_name == "ghcr.io/acme/chart:1.1.0@sha256:helm"
    assert skipped.datasource == "docker"
    assert "not a scannable container image" in skipped.reason

    summary = render_step_summary(report)
    assert "Skipped Update Entries" in summary
    assert "not a scannable container image" in summary
    assert "Vulnerability Scan failed" not in summary

from __future__ import annotations

import sys

from renovate_vuln_report.errors import ScanFailure
from renovate_vuln_report.model import (
    Finding,
    ImageUpdateEntry,
    Report,
    ScanOutcome,
    TargetReport,
    UnsupportedUpdateEntry,
    UpdateEntry,
)
from renovate_vuln_report.scan import Scanner

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "negligible": 4,
    "unknown": 5,
}


def build_report(*, entries: tuple[UpdateEntry, ...], scanner: Scanner) -> Report:
    image_entries = [entry for entry in entries if isinstance(entry, ImageUpdateEntry)]
    skipped_entries = tuple(
        entry for entry in entries if isinstance(entry, UnsupportedUpdateEntry)
    )
    target_counts: dict[str, int] = {}
    for entry in image_entries:
        target_counts[entry.new_revision.reference] = (
            target_counts.get(entry.new_revision.reference, 0) + 1
        )

    target_reports: list[TargetReport] = []
    failed = False
    for scan_target, update_entry_count in target_counts.items():
        try:
            outcome = scanner.scan(scan_target)
        except ScanFailure as error:
            failed = True
            print(error.detail, file=sys.stderr)
            target_reports.append(
                TargetReport(
                    scan_target=scan_target,
                    update_entry_count=update_entry_count,
                    failure_reason=error.public_reason,
                )
            )
        except (
            Exception
        ) as error:  # pragma: no cover - defensive boundary around scanner plugins.
            failed = True
            print(str(error), file=sys.stderr)
            target_reports.append(
                TargetReport(
                    scan_target=scan_target,
                    update_entry_count=update_entry_count,
                    failure_reason="scanner failed unexpectedly",
                )
            )
        else:
            target_reports.append(
                TargetReport(
                    scan_target=scan_target,
                    update_entry_count=update_entry_count,
                    outcome=ScanOutcome(findings=sort_findings(outcome.findings)),
                )
            )

    return Report(
        target_reports=tuple(target_reports),
        skipped_entries=skipped_entries,
        failed=failed,
    )


def render_step_summary(report: Report) -> str:
    lines = ["# Image Update Vulnerability Report", ""]

    if not report.target_reports:
        lines.extend(["No supported Scan Targets were found.", ""])

    for target_report in report.target_reports:
        lines.extend([f"## `{_escape_inline_code(target_report.scan_target)}`", ""])
        if target_report.update_entry_count > 1:
            lines.extend(
                [
                    f"Shared by {target_report.update_entry_count} Image Update Entries.",
                    "",
                ]
            )

        if target_report.failure_reason:
            lines.extend(
                [f"Vulnerability Scan failed: {target_report.failure_reason}", ""]
            )
            continue

        findings = target_report.outcome.findings if target_report.outcome else ()
        lines.extend([_severity_counts_line(findings), ""])
        if not findings:
            lines.extend(["No Vulnerability Findings found.", ""])
            continue

        shown = findings[:20]
        lines.extend(
            [
                "| KEV | EPSS | Severity | Vulnerability | Affected Package | Installed | Fixed |",
                "| --- | ---: | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in shown:
            fixed = ", ".join(finding.fixed_versions) if finding.fixed_versions else ""
            lines.append(
                "| "
                + " | ".join(
                    [
                        "KEV" if finding.kev else "",
                        _format_epss(finding.epss),
                        _escape_table(finding.severity),
                        _vulnerability_link(finding.vulnerability_id),
                        _escape_table(finding.package_name),
                        _escape_table(finding.installed_version),
                        _escape_table(fixed),
                    ]
                )
                + " |"
            )
        lines.append("")
        omitted = len(findings) - len(shown)
        if omitted > 0:
            lines.extend([f"{omitted} additional Vulnerability Findings omitted.", ""])

    if report.skipped_entries:
        lines.extend(["## Skipped Update Entries", ""])
        lines.extend(["| Dependency | Datasource | Reason |", "| --- | --- | --- |"])
        for entry in report.skipped_entries:
            dependency = entry.package_name or entry.dep_name or "<unknown>"
            lines.append(
                "| "
                + " | ".join(
                    [
                        _escape_table(dependency),
                        _escape_table(entry.datasource or "<missing>"),
                        _escape_table(entry.reason),
                    ]
                )
                + " |"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def sort_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    return tuple(sorted(findings, key=_finding_sort_key))


def _finding_sort_key(finding: Finding) -> tuple[bool, bool, float, int, str]:
    severity_rank = SEVERITY_ORDER.get(
        finding.severity.lower(), SEVERITY_ORDER["unknown"]
    )
    return (
        not finding.kev,
        finding.epss is None,
        -(finding.epss or 0),
        severity_rank,
        finding.vulnerability_id,
    )


def _severity_counts_line(findings: tuple[Finding, ...]) -> str:
    if not findings:
        return "Severity counts: none"
    counts: dict[str, int] = {}
    for finding in findings:
        severity = finding.severity.capitalize()
        counts[severity] = counts.get(severity, 0) + 1
    ordered = sorted(
        counts.items(), key=lambda item: SEVERITY_ORDER.get(item[0].lower(), 99)
    )
    return "Severity counts: " + ", ".join(
        f"{severity}: {count}" for severity, count in ordered
    )


def _format_epss(epss: float | None) -> str:
    if epss is None:
        return ""
    return f"{epss:.4g}"


def _vulnerability_link(vulnerability_id: str) -> str:
    escaped_id = _escape_table(vulnerability_id)
    if vulnerability_id.startswith("CVE-"):
        return f"[{escaped_id}](https://nvd.nist.gov/vuln/detail/{escaped_id})"
    if vulnerability_id.startswith("GHSA-"):
        return f"[{escaped_id}](https://github.com/advisories/{escaped_id})"
    return escaped_id


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _escape_inline_code(value: str) -> str:
    return value.replace("`", "\\`")

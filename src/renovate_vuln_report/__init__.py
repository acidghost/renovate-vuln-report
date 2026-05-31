from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

METADATA_NOTE_PATTERN = re.compile(r"<!--\s*renovate:metadata=([^\s]+)\s*-->")
MANAGED_COMMENT_MARKER = "<!-- renovate-vuln-report:managed-comment:v1 -->"
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "negligible": 4,
    "unknown": 5,
}


class RenovateVulnReportError(Exception):
    """Base exception for user-facing failures."""


class NoMetadataNotesError(RenovateVulnReportError):
    """Raised when a pull request body has no Renovate Metadata Notes."""


class MetadataError(RenovateVulnReportError):
    """Raised when a Renovate Metadata Note cannot be decoded or interpreted."""


class PreconditionError(RenovateVulnReportError):
    """Raised when the GitHub Action event context is unsupported."""


class ScanFailure(RenovateVulnReportError):
    """Raised when a Vulnerability Scan fails."""

    def __init__(self, public_reason: str, detail: str | None = None) -> None:
        super().__init__(public_reason)
        self.public_reason = public_reason
        self.detail = detail or public_reason


class ForgePublishError(RenovateVulnReportError):
    """Raised when the selected Forge report surface cannot be published."""


@dataclass(frozen=True)
class PullRequestContext:
    body: str
    repository: str
    number: int


@dataclass(frozen=True)
class ForgeComment:
    id: int
    body: str


@dataclass(frozen=True)
class ImageRevision:
    repository: str
    tag: str | None = None
    digest: str | None = None

    def __post_init__(self) -> None:
        if not self.tag and not self.digest:
            raise ValueError("an Image Revision needs a tag, digest, or both")

    @property
    def reference(self) -> str:
        reference = self.repository
        if self.tag:
            reference = f"{reference}:{self.tag}"
        if self.digest:
            reference = f"{reference}@{self.digest}"
        return reference


@dataclass(frozen=True)
class ImageUpdateEntry:
    repository: str
    new_revision: ImageRevision
    current_revision: ImageRevision | None = None
    dep_name: str | None = None
    manager: str | None = None
    update_type: str | None = None


@dataclass(frozen=True)
class UnsupportedUpdateEntry:
    reason: str
    dep_name: str | None = None
    package_name: str | None = None
    datasource: str | None = None
    manager: str | None = None


UpdateEntry = ImageUpdateEntry | UnsupportedUpdateEntry


@dataclass(frozen=True)
class Finding:
    vulnerability_id: str
    severity: str
    package_name: str
    installed_version: str
    fixed_versions: tuple[str, ...] = ()
    epss: float | None = None
    kev: bool = False


@dataclass(frozen=True)
class ScanOutcome:
    findings: tuple[Finding, ...] = ()


class Scanner(Protocol):
    def scan(self, scan_target: str) -> ScanOutcome: ...


class ForgeCommentClient(Protocol):
    def list_issue_comments(
        self, repository: str, issue_number: int
    ) -> tuple[ForgeComment, ...]: ...

    def create_issue_comment(
        self, repository: str, issue_number: int, body: str
    ) -> None: ...

    def update_issue_comment(
        self, repository: str, comment_id: int, body: str
    ) -> None: ...


@dataclass(frozen=True)
class TargetReport:
    scan_target: str
    update_entry_count: int
    outcome: ScanOutcome | None = None
    failure_reason: str | None = None


@dataclass(frozen=True)
class Report:
    target_reports: tuple[TargetReport, ...]
    skipped_entries: tuple[UnsupportedUpdateEntry, ...] = ()
    failed: bool = False


def collect_update_entries(pr_body: str) -> tuple[UpdateEntry, ...]:
    """Extract Renovate Metadata Notes and interpret them into Update Entries."""

    payloads = extract_metadata_payloads(pr_body)
    return tuple(interpret_payload(payload) for payload in payloads)


def extract_metadata_payloads(pr_body: str) -> tuple[dict[str, Any], ...]:
    matches = list(METADATA_NOTE_PATTERN.finditer(pr_body))
    if not matches:
        raise NoMetadataNotesError("no Renovate Metadata Notes were found")

    payloads: list[dict[str, Any]] = []
    for index, match in enumerate(matches, start=1):
        encoded = match.group(1)
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise MetadataError(
                f"Renovate Metadata Note {index} is not valid base64"
            ) from error

        try:
            payload = json.loads(decoded)
        except json.JSONDecodeError as error:
            raise MetadataError(
                f"Renovate Metadata Note {index} does not contain JSON"
            ) from error

        if not isinstance(payload, dict):
            raise MetadataError(
                f"Renovate Metadata Note {index} payload must be a JSON object"
            )
        payloads.append(payload)
    return tuple(payloads)


def interpret_payload(payload: dict[str, Any]) -> UpdateEntry:
    datasource = _optional_string(payload.get("datasource"))
    dep_name = _optional_string(payload.get("depName"))
    package_name = _optional_string(payload.get("packageName"))
    manager = _optional_string(payload.get("manager"))

    if datasource != "docker":
        return UnsupportedUpdateEntry(
            reason=f"unsupported datasource: {datasource or '<missing>'}",
            dep_name=dep_name,
            package_name=package_name,
            datasource=datasource,
            manager=manager,
        )

    repository = package_name or dep_name
    if not repository:
        return UnsupportedUpdateEntry(
            reason="missing image repository",
            dep_name=dep_name,
            package_name=package_name,
            datasource=datasource,
            manager=manager,
        )

    new_tag = _optional_string(payload.get("newValue"))
    new_digest = _optional_string(payload.get("newDigest"))
    if not new_tag and not new_digest:
        return UnsupportedUpdateEntry(
            reason="missing new image revision selector",
            dep_name=dep_name,
            package_name=package_name,
            datasource=datasource,
            manager=manager,
        )

    current_tag = _optional_string(payload.get("currentValue"))
    current_digest = _optional_string(payload.get("currentDigest"))
    current_revision = (
        ImageRevision(repository=repository, tag=current_tag, digest=current_digest)
        if current_tag or current_digest
        else None
    )

    return ImageUpdateEntry(
        repository=repository,
        current_revision=current_revision,
        new_revision=ImageRevision(
            repository=repository, tag=new_tag, digest=new_digest
        ),
        dep_name=dep_name,
        manager=manager,
        update_type=_optional_string(payload.get("updateType")),
    )


def findings_from_grype_json(document: dict[str, Any]) -> tuple[Finding, ...]:
    matches = document.get("matches", [])
    if not isinstance(matches, list):
        return ()

    findings: list[Finding] = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
            continue

        vulnerability_id = _optional_string(vulnerability.get("id")) or "<unknown>"
        severity = _optional_string(vulnerability.get("severity")) or "Unknown"
        package_name = _optional_string(artifact.get("name")) or "<unknown>"
        installed_version = _optional_string(artifact.get("version")) or "<unknown>"
        fixed_versions = _fixed_versions(vulnerability.get("fix"))
        epss = _epss(vulnerability.get("epss"))
        kev = _kev(vulnerability)

        findings.append(
            Finding(
                vulnerability_id=vulnerability_id,
                severity=severity,
                package_name=package_name,
                installed_version=installed_version,
                fixed_versions=fixed_versions,
                epss=epss,
                kev=kev,
            )
        )

    return tuple(findings)


class HttpForgeCommentClient:
    def __init__(self, *, forge: str, api_url: str, token: str) -> None:
        self.forge = forge
        self.api_url = api_url.rstrip("/")
        self.token = token

    def list_issue_comments(
        self, repository: str, issue_number: int
    ) -> tuple[ForgeComment, ...]:
        data = self._request_json(
            "GET",
            f"/repos/{repository}/issues/{issue_number}/comments?per_page=100&limit=100",
        )
        if not isinstance(data, list):
            raise ForgePublishError("Forge returned an unexpected comments response")

        comments: list[ForgeComment] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            comment_id = item.get("id")
            body = item.get("body")
            if isinstance(comment_id, int) and isinstance(body, str):
                comments.append(ForgeComment(id=comment_id, body=body))
        return tuple(comments)

    def create_issue_comment(
        self, repository: str, issue_number: int, body: str
    ) -> None:
        self._request_json(
            "POST",
            f"/repos/{repository}/issues/{issue_number}/comments",
            body={"body": body},
        )

    def update_issue_comment(self, repository: str, comment_id: int, body: str) -> None:
        self._request_json(
            "PATCH",
            f"/repos/{repository}/issues/comments/{comment_id}",
            body={"body": body},
        )

    def _request_json(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> Any:
        request_body = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=request_body,
            method=method,
            headers=self._headers(),
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                response_body = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")
            raise ForgePublishError(
                f"Forge API request failed with status {error.code}: {_first_non_empty_line(detail) or error.reason}"
            ) from error
        except urllib.error.URLError as error:
            raise ForgePublishError(
                f"Forge API request failed: {error.reason}"
            ) from error

        if not response_body:
            return None
        try:
            return json.loads(response_body)
        except json.JSONDecodeError as error:
            raise ForgePublishError("Forge API returned invalid JSON") from error

    def _headers(self) -> dict[str, str]:
        authorization = (
            f"Bearer {self.token}" if self.forge == "github" else f"token {self.token}"
        )
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "renovate-vuln-report",
            "Authorization": authorization,
        }


class GrypeScanner:
    def scan(self, scan_target: str) -> ScanOutcome:
        command = ["grype", "-o", "json", f"registry:{scan_target}"]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as error:
            raise ScanFailure(
                "grype is not installed or not available on PATH", str(error)
            ) from error

        if completed.returncode != 0:
            public_reason = _first_non_empty_line(completed.stderr) or (
                f"grype exited with status {completed.returncode}"
            )
            raise ScanFailure(public_reason=public_reason, detail=completed.stderr)

        try:
            grype_json = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise ScanFailure(
                "grype did not return valid JSON", completed.stdout
            ) from error

        if not isinstance(grype_json, dict):
            raise ScanFailure("grype JSON output was not an object", completed.stdout)
        return ScanOutcome(findings=findings_from_grype_json(grype_json))


def run(
    *,
    event_name: str,
    event_path: Path,
    summary_path: Path | None,
    scanner: Scanner,
    report_surface: str = "summary",
    comment_client: ForgeCommentClient | None = None,
) -> int:
    context: PullRequestContext | None = None
    try:
        context = _pull_request_context(event_name=event_name, event_path=event_path)
        entries = collect_update_entries(context.body)
    except RenovateVulnReportError as error:
        content = f"# Image Update Vulnerability Report\n\nFailed: {error}\n"
        _publish_report(
            report_surface=report_surface,
            markdown=content,
            summary_path=summary_path,
            context=context,
            comment_client=comment_client,
        )
        print(str(error), file=sys.stderr)
        return 1

    report = build_report(entries=entries, scanner=scanner)
    markdown = render_step_summary(report)
    publish_failed = _publish_report(
        report_surface=report_surface,
        markdown=markdown,
        summary_path=summary_path,
        context=context,
        comment_client=comment_client,
    )
    return 1 if report.failed or publish_failed else 0


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


def publish_managed_pull_request_comment(
    *,
    comment_client: ForgeCommentClient,
    repository: str,
    issue_number: int,
    markdown: str,
) -> None:
    body = f"{MANAGED_COMMENT_MARKER}\n{markdown}"
    comments = comment_client.list_issue_comments(repository, issue_number)
    for comment in comments:
        if comment.body.startswith(MANAGED_COMMENT_MARKER):
            comment_client.update_issue_comment(repository, comment.id, body)
            return
    comment_client.create_issue_comment(repository, issue_number, body)


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


def _publish_report(
    *,
    report_surface: str,
    markdown: str,
    summary_path: Path | None,
    context: PullRequestContext | None,
    comment_client: ForgeCommentClient | None,
) -> bool:
    if report_surface == "summary":
        _write_summary(summary_path, markdown)
        return False

    if report_surface != "pr-comment":
        print(f"unsupported report surface: {report_surface}", file=sys.stderr)
        return True

    if context is None:
        print(
            "cannot publish Pull Request Comment without pull request context",
            file=sys.stderr,
        )
        return True
    if comment_client is None:
        print(
            "cannot publish Pull Request Comment without a Forge client",
            file=sys.stderr,
        )
        return True

    try:
        publish_managed_pull_request_comment(
            comment_client=comment_client,
            repository=context.repository,
            issue_number=context.number,
            markdown=markdown,
        )
    except ForgePublishError as error:
        print(str(error), file=sys.stderr)
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--report-surface",
        choices=("summary", "pr-comment"),
        default=os.environ.get("RENOVATE_VULN_REPORT_SURFACE", "summary"),
    )
    parser.add_argument(
        "--forge",
        choices=("github", "forgejo", "gitea"),
        default=os.environ.get("RENOVATE_VULN_REPORT_FORGE", "github"),
    )
    parser.add_argument(
        "--forge-api-url",
        default=os.environ.get("GITHUB_API_URL") or "https://api.github.com",
    )
    args = parser.parse_args()

    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    event_path_value = os.environ.get("GITHUB_EVENT_PATH")
    summary_path_value = os.environ.get("GITHUB_STEP_SUMMARY")
    if not event_path_value:
        print("GITHUB_EVENT_PATH is not set", file=sys.stderr)
        raise SystemExit(1)

    comment_client = None
    if args.report_surface == "pr-comment":
        token = os.environ.get("FORGE_TOKEN")
        if not token:
            print(
                "FORGE_TOKEN is required when report-surface is pr-comment",
                file=sys.stderr,
            )
            raise SystemExit(1)
        comment_client = HttpForgeCommentClient(
            forge=args.forge, api_url=args.forge_api_url, token=token
        )

    exit_code = run(
        event_name=event_name,
        event_path=Path(event_path_value),
        summary_path=Path(summary_path_value) if summary_path_value else None,
        scanner=GrypeScanner(),
        report_surface=args.report_surface,
        comment_client=comment_client,
    )
    raise SystemExit(exit_code)


def _pull_request_context(*, event_name: str, event_path: Path) -> PullRequestContext:
    if event_name != "pull_request":
        raise PreconditionError(
            "renovate-vuln-report only supports pull_request events"
        )

    try:
        event = json.loads(event_path.read_text())
    except FileNotFoundError as error:
        raise PreconditionError(
            f"GitHub event payload not found: {event_path}"
        ) from error
    except json.JSONDecodeError as error:
        raise PreconditionError("GitHub event payload is not valid JSON") from error

    if not isinstance(event, dict):
        raise PreconditionError("GitHub event payload is not a JSON object")

    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        raise PreconditionError("GitHub event payload has no pull_request object")

    body = pull_request.get("body")
    if not isinstance(body, str):
        raise PreconditionError("pull request body is unavailable")

    number = pull_request.get("number")
    if not isinstance(number, int):
        raise PreconditionError("pull request number is unavailable")

    repository = event.get("repository")
    if not isinstance(repository, dict):
        raise PreconditionError("repository information is unavailable")

    repository_full_name = repository.get("full_name")
    if not isinstance(repository_full_name, str):
        raise PreconditionError("repository full name is unavailable")

    return PullRequestContext(
        body=body,
        repository=repository_full_name,
        number=number,
    )


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    value = value.strip()
    return value or None


def _fixed_versions(fix: Any) -> tuple[str, ...]:
    if not isinstance(fix, dict):
        return ()
    versions = fix.get("versions", [])
    if not isinstance(versions, list):
        return ()
    return tuple(str(version) for version in versions if version is not None)


def _epss(value: Any) -> float | None:
    candidates: list[float] = []
    if isinstance(value, int | float):
        candidates.append(float(value))
    elif isinstance(value, dict):
        score = value.get("epss") or value.get("score")
        if isinstance(score, int | float):
            candidates.append(float(score))
    elif isinstance(value, list):
        for item in value:
            score = item.get("epss") if isinstance(item, dict) else item
            if isinstance(score, int | float):
                candidates.append(float(score))
    return max(candidates) if candidates else None


def _kev(vulnerability: dict[str, Any]) -> bool:
    known_exploited = vulnerability.get("knownExploited")
    if isinstance(known_exploited, bool):
        return known_exploited
    if isinstance(known_exploited, list):
        return len(known_exploited) > 0
    kev = vulnerability.get("kev")
    return bool(kev)


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


def _first_non_empty_line(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def _write_summary(summary_path: Path | None, content: str) -> None:
    if summary_path is None:
        print(content)
        return
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(content)

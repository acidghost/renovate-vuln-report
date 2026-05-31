from __future__ import annotations

import json
import subprocess
from typing import Any, Protocol

from renovate_vuln_report.errors import ScanFailure
from renovate_vuln_report.model import Finding, ScanOutcome


class Scanner(Protocol):
    def scan(self, scan_target: str) -> ScanOutcome: ...


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


def _first_non_empty_line(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None

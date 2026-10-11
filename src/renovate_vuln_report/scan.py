from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Protocol

from renovate_vuln_report.errors import ScanFailure, UnsupportedScanTarget
from renovate_vuln_report.model import Finding, ScanOutcome
from renovate_vuln_report.oci import (
    FetchedManifest,
    ManifestFetcher,
    classify_manifest,
    make_default_manifest_fetcher,
)
from renovate_vuln_report.scan_cache import ScanCache

logger = logging.getLogger(__name__)


class Scanner(Protocol):
    def scan(self, scan_target: str) -> ScanOutcome: ...


class GrypeScanner:
    def __init__(
        self,
        manifest_fetcher: ManifestFetcher | None = None,
        cache_dir: Path | None = None,
    ) -> None:
        # When None, the production fetcher is built lazily on first scan so
        # tests can inject a double and avoid network access.
        self._manifest_fetcher = manifest_fetcher
        self._cache = ScanCache(cache_dir) if cache_dir is not None else None
        self.cache_updated = False

    def scan(self, scan_target: str) -> ScanOutcome:
        manifest = self._fetch_manifest(scan_target)
        if manifest is not None:
            classification = classify_manifest(manifest.document)
            logger.debug(
                "OCI manifest for %s classified as %s", scan_target, classification.kind
            )
            if classification.skip_reason is not None:
                raise UnsupportedScanTarget(
                    public_reason=classification.skip_reason,
                    detail=f"OCI manifest classified as {classification.kind}",
                )

        env = os.environ.copy()
        env.setdefault("GRYPE_CHECK_FOR_APP_UPDATE", "false")
        cache_path = None
        immutable_target = _immutable_target(scan_target, manifest)
        if self._cache is not None and immutable_target is not None:
            cache_path = self._cache.path_for(immutable_target, env)
        elif self._cache is not None:
            logger.debug("Scan cache bypassed: no immutable digest for %s", scan_target)
        if cache_path is not None:
            cached = ScanCache.load(cache_path)
            if cached is not None:
                logger.info("Reusing cached Vulnerability Scan: %s", scan_target)
                return ScanOutcome(findings=findings_from_grype_json(cached))
            logger.debug("Scan cache miss for %s", scan_target)

        # Pin a resolved tag before scanning so a concurrent tag move cannot
        # store results for different content under the resolved digest.
        target = immutable_target if cache_path is not None else scan_target
        command = ["grype", "-o", "json", f"registry:{target}"]
        logger.debug("Running Grype for %s", target)
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                env=env,
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
        if cache_path is not None and ScanCache.save(cache_path, grype_json):
            self.cache_updated = True
            logger.debug("Saved Vulnerability Scan to cache for %s", scan_target)
        return ScanOutcome(findings=findings_from_grype_json(grype_json))

    def _fetch_manifest(self, scan_target: str) -> FetchedManifest | None:
        fetcher = self._manifest_fetcher or make_default_manifest_fetcher()
        self._manifest_fetcher = fetcher
        return fetcher.fetch(scan_target)


def _immutable_target(target: str, manifest: FetchedManifest | None) -> str | None:
    reference, separator, digest = target.partition("@")
    if not separator:
        digest = manifest.digest if manifest is not None else None
    if not digest or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        return None
    # Strip a tag but preserve a registry port.
    repository, slash, name = reference.rpartition("/")
    name = name.partition(":")[0]
    return f"{repository}{slash}{name}@{digest}"


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

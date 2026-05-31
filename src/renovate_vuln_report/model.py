from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PullRequestContext:
    body: str
    repository: str
    number: int


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

from __future__ import annotations


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


class UnsupportedScanTarget(RenovateVulnReportError):
    """Raised when a Scan Target is not a scannable container image.

    For example a Helm chart or other non-image OCI artifact that Grype
    cannot catalog. Such targets are out of scope and are recorded as a
    Skipped Update Entry rather than a failed Vulnerability Scan.
    """

    def __init__(self, public_reason: str, detail: str | None = None) -> None:
        super().__init__(public_reason)
        self.public_reason = public_reason
        self.detail = detail or public_reason


class ForgePublishError(RenovateVulnReportError):
    """Raised when the selected Forge report surface cannot be published."""

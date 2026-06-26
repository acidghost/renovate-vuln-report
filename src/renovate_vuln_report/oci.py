"""OCI manifest inspection and artifact classification.

A registry reference is not always a runnable container image: Helm charts,
cosign signatures, SBOMs and other OCI artifacts live behind the same
``registry:`` reference shape. Grype can only scan container images, so before
invoking it we inspect the OCI manifest to decide whether a Scan Target is a
scannable image or an out-of-scope artifact.

The classifier is intentionally conservative: it only reports a skip reason
when it *positively* identifies a non-image artifact. Anything ambiguous is
classified as ``unknown`` and left to the scanner. This guarantees that
classification can never introduce a new failure -- it can only turn former
scan failures into clean skips, and a manifest that cannot be fetched simply
falls through to a normal scan.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

# Media types that mark a manifest as an OCI/Docker image index (multi-arch).
IMAGE_INDEX_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)

# Media types of the config blob of a scannable container image.
CONTAINER_CONFIG_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.config.v1+json",
        "application/vnd.docker.container.image.v1+json",
    }
)

# Helm chart packaged as an OCI artifact.
HELM_CONFIG_MEDIA_TYPE = "application/vnd.cncf.helm.config.v1+json"
HELM_CHART_LAYER_MEDIA_TYPE = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"

# Classification kinds.
KIND_CONTAINER_IMAGE = "container-image"
KIND_HELM_CHART = "helm-chart"
KIND_OTHER_ARTIFACT = "other-artifact"
KIND_UNKNOWN = "unknown"


@dataclass(frozen=True)
class Classification:
    """The result of classifying one OCI manifest.

    ``skip_reason`` is ``None`` when the target is a container image or could
    not be determined (the caller should proceed to scan); a reason string
    when positively identified as a non-image artifact.
    """

    kind: str
    skip_reason: str | None


def classify_manifest(manifest: dict[str, Any]) -> Classification:
    """Classify an OCI manifest as a scannable container image or not.

    Pure function over the manifest document; safe to unit-test without any
    network access.
    """
    media_type = manifest.get("mediaType")
    config = manifest.get("config")
    config_media_type = config.get("mediaType") if isinstance(config, dict) else None

    # A multi-arch image index is always a container image, never a chart.
    if media_type in IMAGE_INDEX_MEDIA_TYPES:
        return Classification(kind=KIND_CONTAINER_IMAGE, skip_reason=None)

    # A Helm chart is identifiable by its config media type. This is the
    # case from the field: the chart manifest is structurally an OCI image
    # manifest, and only the config type distinguishes it.
    if config_media_type == HELM_CONFIG_MEDIA_TYPE:
        return Classification(
            kind=KIND_HELM_CHART,
            skip_reason=(
                "not a scannable container image: Helm chart distributed as "
                "an OCI artifact"
            ),
        )

    # Defend against odd manifests that carry the Helm layer without the
    # canonical config media type.
    if _has_layer(manifest, HELM_CHART_LAYER_MEDIA_TYPE):
        return Classification(
            kind=KIND_HELM_CHART,
            skip_reason=(
                "not a scannable container image: Helm chart distributed as "
                "an OCI artifact"
            ),
        )

    # A genuine container image config: scannable.
    if config_media_type in CONTAINER_CONFIG_MEDIA_TYPES:
        return Classification(kind=KIND_CONTAINER_IMAGE, skip_reason=None)

    # An image manifest carrying some other config type is a different kind
    # of OCI artifact (cosign signature, SBOM, ...): skip with the real type.
    if config_media_type:
        return Classification(
            kind=KIND_OTHER_ARTIFACT,
            skip_reason=(
                "not a scannable container image: OCI artifact "
                f"(config media type {config_media_type})"
            ),
        )

    # OCI 1.1 artifactType on the manifest with no config blob.
    artifact_type = manifest.get("artifactType")
    if isinstance(artifact_type, str) and artifact_type:
        return Classification(
            kind=KIND_OTHER_ARTIFACT,
            skip_reason=(
                "not a scannable container image: OCI artifact "
                f"(artifact type {artifact_type})"
            ),
        )

    # Could not classify: let the scanner decide. A non-image artifact we
    # fail to recognize here will surface as a grype failure rather than a
    # clean skip -- the cost of not coupling to grype's error wording.
    return Classification(kind=KIND_UNKNOWN, skip_reason=None)


def _has_layer(manifest: dict[str, Any], media_type: str) -> bool:
    layers = manifest.get("layers")
    if not isinstance(layers, list):
        return False
    return any(
        isinstance(layer, dict) and layer.get("mediaType") == media_type
        for layer in layers
    )


class ManifestFetcher(Protocol):
    def fetch(self, reference: str) -> dict[str, Any] | None:
        """Return the OCI manifest for ``reference`` or ``None`` if it cannot
        be fetched. Returning ``None`` triggers the scanner fallback."""
        ...


class NullManifestFetcher:
    """A fetcher that never classifies -- always proceeds to the scanner.

    Useful in tests and as a future kill-switch for manifest-based
    classification.
    """

    def fetch(self, reference: str) -> dict[str, Any] | None:  # noqa: ARG002
        return None


class OrasManifestFetcher:
    """Fetches OCI manifests via oras with a hard wall-clock bound.

    oras issues HTTP requests without a per-request timeout and retries with
    exponential backoff, which could stall a CI job indefinitely on a hung
    connection or for tens of seconds on a missing manifest. The fetch is run
    on a daemon thread with a deadline: if it does not complete in time we
    abandon it and fall back to the scanner.
    """

    def __init__(self, timeout_seconds: float = 15.0) -> None:
        self._timeout_seconds = timeout_seconds

    def fetch(self, reference: str) -> dict[str, Any] | None:
        return _fetch_manifest_bounded(reference, self._timeout_seconds)


def _fetch_manifest_bounded(
    reference: str, timeout_seconds: float
) -> dict[str, Any] | None:
    import oras.provider  # local import keeps the pure classifier dependency-free

    outcome: dict[str, Any] | None = None

    def _work() -> None:
        nonlocal outcome
        try:
            registry = oras.provider.Registry()
            outcome = registry.get_manifest(reference)
        except Exception:
            # Network, auth, not-found, malformed manifest, or an oras bug:
            # we cannot classify reliably, so fall back to the scanner.
            outcome = None

    worker = threading.Thread(target=_work, daemon=True)
    worker.start()
    worker.join(timeout_seconds)
    if worker.is_alive():
        # Timed out; the daemon thread is abandoned and will not block exit.
        return None
    return outcome


def make_default_manifest_fetcher() -> ManifestFetcher:
    """Construct the production manifest fetcher."""
    return OrasManifestFetcher()


# Kept as a Callable type alias for callers that inject simple functions.
ManifestFetcherFn = Callable[[str], "dict[str, Any] | None"]

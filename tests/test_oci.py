from __future__ import annotations

from typing import Any

from renovate_vuln_report import (
    HELM_CONFIG_MEDIA_TYPE,
    KIND_CONTAINER_IMAGE,
    KIND_HELM_CHART,
    KIND_OTHER_ARTIFACT,
    KIND_UNKNOWN,
    Classification,
    NullManifestFetcher,
    classify_manifest,
)


def helm_chart_manifest() -> dict[str, Any]:
    """A Helm chart packaged as an OCI artifact (the librechat case)."""
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": HELM_CONFIG_MEDIA_TYPE,
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


def container_image_manifest() -> dict[str, Any]:
    return {
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


def docker_image_manifest() -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": "sha256:5555",
            "size": 7023,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "digest": "sha256:6666",
                "size": 31337,
            }
        ],
    }


def image_index_manifest() -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:7777",
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    }


def cosign_signature_manifest() -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
            "digest": "sha256:8888",
            "size": 255,
        },
        "layers": [],
    }


def test_classify_helm_chart_is_skipped_with_precise_reason() -> None:
    result = classify_manifest(helm_chart_manifest())
    assert result == Classification(
        kind=KIND_HELM_CHART,
        skip_reason=(
            "not a scannable container image: Helm chart distributed as an OCI artifact"
        ),
    )


def test_classify_helm_layer_without_canonical_config_is_still_helm() -> None:
    manifest = helm_chart_manifest()
    manifest["config"]["mediaType"] = "application/vnd.oci.empty.v1+json"
    assert classify_manifest(manifest).kind == KIND_HELM_CHART


def test_classify_oci_container_image_is_scannable() -> None:
    result = classify_manifest(container_image_manifest())
    assert result == Classification(kind=KIND_CONTAINER_IMAGE, skip_reason=None)


def test_classify_docker_container_image_is_scannable() -> None:
    result = classify_manifest(docker_image_manifest())
    assert result.kind == KIND_CONTAINER_IMAGE
    assert result.skip_reason is None


def test_classify_image_index_is_scannable() -> None:
    result = classify_manifest(image_index_manifest())
    assert result.kind == KIND_CONTAINER_IMAGE
    assert result.skip_reason is None


def test_classify_other_artifact_reports_its_config_media_type() -> None:
    result = classify_manifest(cosign_signature_manifest())
    assert result.kind == KIND_OTHER_ARTIFACT
    assert result.skip_reason is not None
    assert "application/vnd.dev.cosign.simplesigning.v1+json" in result.skip_reason


def test_classify_oci11_artifact_type_is_other_artifact() -> None:
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.example.wasm.v1",
        "config": None,
        "layers": [],
    }
    result = classify_manifest(manifest)
    assert result.kind == KIND_OTHER_ARTIFACT
    assert "application/vnd.example.wasm.v1" in (result.skip_reason or "")


def test_classify_unknown_manifest_proceeds_to_scanner() -> None:
    # No config, no index, no artifact type: cannot classify -> proceed.
    result = classify_manifest({"schemaVersion": 2, "mediaType": "weird/type"})
    assert result == Classification(kind=KIND_UNKNOWN, skip_reason=None)


def test_null_manifest_fetcher_never_classifies() -> None:
    assert NullManifestFetcher().fetch("ghcr.io/acme/app:1.0.0") is None

from __future__ import annotations

import base64
from collections.abc import Callable

import pytest

from renovate_vuln_report import (
    ImageUpdateEntry,
    MetadataError,
    NoMetadataNotesError,
    UnsupportedUpdateEntry,
    collect_update_entries,
)


def test_collect_update_entries_interprets_image_updates_and_skipped_entries(
    note: Callable[[dict[str, object]], str],
    docker_payload: Callable[..., dict[str, object]],
) -> None:
    body = "\n".join(
        [
            note(docker_payload()),
            note(
                {
                    "depName": "lodash",
                    "packageName": "lodash",
                    "manager": "npm",
                    "datasource": "npm",
                    "updateType": "patch",
                    "currentValue": "1.0.0",
                    "newValue": "1.0.1",
                    "currentDigest": None,
                    "newDigest": None,
                }
            ),
        ]
    )

    image_entry, skipped_entry = collect_update_entries(body)

    assert isinstance(image_entry, ImageUpdateEntry)
    assert image_entry.repository == "ghcr.io/acme/app"
    assert image_entry.current_revision is not None
    assert image_entry.current_revision.reference == "ghcr.io/acme/app:1.0.0@sha256:aaa"
    assert image_entry.new_revision.reference == "ghcr.io/acme/app:1.1.0@sha256:bbb"

    assert isinstance(skipped_entry, UnsupportedUpdateEntry)
    assert skipped_entry.reason == "unsupported datasource: npm"


def test_collect_update_entries_uses_dep_name_when_package_name_is_absent(
    note: Callable[[dict[str, object]], str],
    docker_payload: Callable[..., dict[str, object]],
) -> None:
    (entry,) = collect_update_entries(note(docker_payload(packageName=None)))

    assert isinstance(entry, ImageUpdateEntry)
    assert entry.repository == "ghcr.io/acme/display-name"


def test_collect_update_entries_rejects_missing_and_malformed_notes() -> None:
    with pytest.raises(NoMetadataNotesError):
        collect_update_entries("ordinary pull request body")

    with pytest.raises(MetadataError):
        collect_update_entries("<!-- renovate:metadata=not-base64 -->")

    encoded_list = base64.b64encode(b"[]").decode()
    with pytest.raises(MetadataError):
        collect_update_entries(f"<!-- renovate:metadata={encoded_list} -->")

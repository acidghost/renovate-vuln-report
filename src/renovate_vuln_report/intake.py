from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path
from typing import Any

from renovate_vuln_report.errors import (
    MetadataError,
    NoMetadataNotesError,
    PreconditionError,
)
from renovate_vuln_report.model import (
    ImageRevision,
    ImageUpdateEntry,
    PullRequestContext,
    UnsupportedUpdateEntry,
    UpdateEntry,
)

METADATA_NOTE_PATTERN = re.compile(r"<!--\s*renovate:metadata=([^\s]+)\s*-->")


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


def pull_request_context(*, event_name: str, event_path: Path) -> PullRequestContext:
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

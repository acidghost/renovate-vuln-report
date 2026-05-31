from __future__ import annotations

import base64
import json
from collections.abc import Callable

import pytest

from renovate_vuln_report import ForgeComment, ForgePublishError, ScanOutcome


def _note(payload: dict[str, object]) -> str:
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    return f"<!-- renovate:metadata={encoded} -->"


def _docker_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "depName": "ghcr.io/acme/display-name",
        "packageName": "ghcr.io/acme/app",
        "manager": "dockerfile",
        "datasource": "docker",
        "updateType": "minor",
        "currentValue": "1.0.0",
        "newValue": "1.1.0",
        "currentDigest": "sha256:aaa",
        "newDigest": "sha256:bbb",
    }
    payload.update(overrides)
    return payload


def _pull_request_event(body: str) -> dict[str, object]:
    return {
        "repository": {"full_name": "acme/widgets"},
        "pull_request": {"number": 17, "body": body},
    }


class FakeScanner:
    def __init__(self, outcomes: dict[str, ScanOutcome | Exception]) -> None:
        self.outcomes = outcomes
        self.scanned: list[str] = []

    def scan(self, scan_target: str) -> ScanOutcome:
        self.scanned.append(scan_target)
        outcome = self.outcomes[scan_target]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeCommentClient:
    def __init__(self, comments: tuple[ForgeComment, ...] = ()) -> None:
        self.comments = list(comments)
        self.created: list[tuple[str, int, str]] = []
        self.updated: list[tuple[str, int, str]] = []

    def list_issue_comments(
        self, repository: str, issue_number: int
    ) -> tuple[ForgeComment, ...]:
        return tuple(self.comments)

    def create_issue_comment(
        self, repository: str, issue_number: int, body: str
    ) -> None:
        self.created.append((repository, issue_number, body))

    def update_issue_comment(self, repository: str, comment_id: int, body: str) -> None:
        self.updated.append((repository, comment_id, body))


class FailingCommentClient:
    def list_issue_comments(
        self, repository: str, issue_number: int
    ) -> tuple[ForgeComment, ...]:
        raise ForgePublishError("comment permission denied")

    def create_issue_comment(
        self, repository: str, issue_number: int, body: str
    ) -> None:
        raise AssertionError("not reached")

    def update_issue_comment(self, repository: str, comment_id: int, body: str) -> None:
        raise AssertionError("not reached")


@pytest.fixture
def note() -> Callable[[dict[str, object]], str]:
    return _note


@pytest.fixture
def docker_payload() -> Callable[..., dict[str, object]]:
    return _docker_payload


@pytest.fixture
def pull_request_event() -> Callable[[str], dict[str, object]]:
    return _pull_request_event

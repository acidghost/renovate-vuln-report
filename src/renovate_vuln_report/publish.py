from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from renovate_vuln_report.errors import ForgePublishError
from renovate_vuln_report.model import PullRequestContext

MANAGED_COMMENT_MARKER = "<!-- renovate-vuln-report:managed-comment:v1 -->"


@dataclass(frozen=True)
class ForgeComment:
    id: int
    body: str


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


def publish_report(
    *,
    report_surface: str,
    markdown: str,
    summary_path: Path | None,
    context: PullRequestContext | None,
    comment_client: ForgeCommentClient | None,
) -> bool:
    if report_surface == "summary":
        write_summary(summary_path, markdown)
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


def write_summary(summary_path: Path | None, content: str) -> None:
    if summary_path is None:
        print(content)
        return
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(content)


def _first_non_empty_line(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None

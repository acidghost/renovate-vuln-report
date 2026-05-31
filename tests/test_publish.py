from __future__ import annotations

from renovate_vuln_report import (
    ForgeComment,
    PullRequestContext,
    publish_managed_pull_request_comment,
    publish_report,
)

from conftest import FailingCommentClient, FakeCommentClient


def test_publish_managed_pull_request_comment_creates_comment() -> None:
    comment_client = FakeCommentClient()

    publish_managed_pull_request_comment(
        comment_client=comment_client,
        repository="acme/widgets",
        issue_number=17,
        markdown="# Image Update Vulnerability Report\n",
    )

    assert len(comment_client.created) == 1
    repository, issue_number, body = comment_client.created[0]
    assert repository == "acme/widgets"
    assert issue_number == 17
    assert body.startswith("<!-- renovate-vuln-report:managed-comment:v1 -->")
    assert "# Image Update Vulnerability Report" in body


def test_publish_managed_pull_request_comment_updates_existing_comment() -> None:
    comment_client = FakeCommentClient(
        comments=(
            ForgeComment(id=41, body="ordinary human comment"),
            ForgeComment(
                id=42,
                body="<!-- renovate-vuln-report:managed-comment:v1 -->\nold report",
            ),
        )
    )

    publish_managed_pull_request_comment(
        comment_client=comment_client,
        repository="acme/widgets",
        issue_number=17,
        markdown="# Image Update Vulnerability Report\n",
    )

    assert comment_client.created == []
    assert len(comment_client.updated) == 1
    repository, comment_id, body = comment_client.updated[0]
    assert repository == "acme/widgets"
    assert comment_id == 42
    assert body.startswith("<!-- renovate-vuln-report:managed-comment:v1 -->")
    assert "# Image Update Vulnerability Report" in body


def test_publish_report_returns_failure_when_pull_request_comment_cannot_publish() -> (
    None
):
    failed = publish_report(
        report_surface="pr-comment",
        markdown="# Image Update Vulnerability Report\n",
        summary_path=None,
        context=PullRequestContext(body="", repository="acme/widgets", number=17),
        comment_client=FailingCommentClient(),
    )

    assert failed is True

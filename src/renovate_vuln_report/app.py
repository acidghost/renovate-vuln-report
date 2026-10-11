from __future__ import annotations

import logging
from pathlib import Path

from renovate_vuln_report.errors import RenovateVulnReportError
from renovate_vuln_report.intake import collect_update_entries, pull_request_context
from renovate_vuln_report.publish import ForgeCommentClient, publish_report
from renovate_vuln_report.report import build_report, render_step_summary
from renovate_vuln_report.scan import Scanner

logger = logging.getLogger(__name__)


def run(
    *,
    event_name: str,
    event_path: Path,
    summary_path: Path | None,
    scanner: Scanner,
    report_surface: str = "summary",
    comment_client: ForgeCommentClient | None = None,
) -> int:
    context = None
    logger.debug("Reading pull request event from %s", event_path)
    try:
        context = pull_request_context(event_name=event_name, event_path=event_path)
        logger.info("Processing Renovate PR %s#%s", context.repository, context.number)
        entries = collect_update_entries(context.body)
        logger.info("Collected %d Update Entries", len(entries))
    except RenovateVulnReportError as error:
        content = f"# Image Update Vulnerability Report\n\nFailed: {error}\n"
        publish_report(
            report_surface=report_surface,
            markdown=content,
            summary_path=summary_path,
            context=context,
            comment_client=comment_client,
        )
        logger.error("Cannot build Vulnerability Report: %s", error)
        return 1

    report = build_report(entries=entries, scanner=scanner)
    markdown = render_step_summary(report)
    publish_failed = publish_report(
        report_surface=report_surface,
        markdown=markdown,
        summary_path=summary_path,
        context=context,
        comment_client=comment_client,
    )
    exit_code = 1 if report.failed or publish_failed else 0
    logger.info(
        "Report complete: %d Scan Targets, %d Skipped Update Entries, exit status %d",
        len(report.target_reports),
        len(report.skipped_entries),
        exit_code,
    )
    return exit_code

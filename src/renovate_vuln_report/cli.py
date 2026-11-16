from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from renovate_vuln_report.app import run
from renovate_vuln_report.errors import RenovateVulnReportError
from renovate_vuln_report.intake import collect_update_entries, pull_request_context
from renovate_vuln_report.model import ImageUpdateEntry
from renovate_vuln_report.publish import HttpForgeCommentClient
from renovate_vuln_report.scan import GrypeScanner

logger = logging.getLogger(__name__)
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def _log_level(value: str) -> str:
    level = value.upper()
    if level not in LOG_LEVELS:
        raise argparse.ArgumentTypeError(
            f"invalid log level: {value!r}; choose from {', '.join(LOG_LEVELS).lower()}"
        )
    return level


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Write needs-scanning to GITHUB_OUTPUT without scanning or publishing",
    )
    parser.add_argument(
        "--report-surface",
        choices=("summary", "pr-comment"),
        default=os.environ.get("RENOVATE_VULN_REPORT_SURFACE", "summary"),
    )
    parser.add_argument(
        "--forge",
        choices=("github", "forgejo", "gitea"),
        default=os.environ.get("RENOVATE_VULN_REPORT_FORGE", "github"),
    )
    parser.add_argument(
        "--forge-api-url",
        default=os.environ.get("GITHUB_API_URL") or "https://api.github.com",
    )
    parser.add_argument(
        "--scan-cache-dir",
        type=Path,
        default=os.environ.get("RENOVATE_VULN_REPORT_SCAN_CACHE_DIR"),
        help="Cache successful scans (requires GRYPE_DB_AUTO_UPDATE=false)",
    )
    parser.add_argument(
        "--log-level",
        type=_log_level,
        choices=LOG_LEVELS,
        default=os.environ.get("RENOVATE_VULN_REPORT_LOG_LEVEL")
        or ("debug" if os.environ.get("RUNNER_DEBUG") == "1" else "info"),
        help="Logging verbosity (default: debug when RUNNER_DEBUG=1, otherwise info; case-insensitive)",
    )
    args = parser.parse_args()

    # Keep dependency loggers at warning: registry HTTP debug logs can expose
    # credentials. Only our package follows the user's verbosity setting.
    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s"
    )
    logging.getLogger("renovate_vuln_report").setLevel(args.log_level)

    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    event_path_value = os.environ.get("GITHUB_EVENT_PATH")
    summary_path_value = os.environ.get("GITHUB_STEP_SUMMARY")
    if not event_path_value:
        logger.error("GITHUB_EVENT_PATH is not set")
        raise SystemExit(1)

    if args.preflight:
        # Let the normal report run publish intake failures rather than failing
        # in database/cache setup before a report can be produced.
        needs_scanning = False
        try:
            context = pull_request_context(
                event_name=event_name, event_path=Path(event_path_value)
            )
            entries = collect_update_entries(context.body)
            needs_scanning = any(
                isinstance(entry, ImageUpdateEntry) for entry in entries
            )
        except RenovateVulnReportError:
            logger.debug("Preflight deferred an intake failure to the reporting step")
        output_path = os.environ.get("GITHUB_OUTPUT")
        if output_path:
            with Path(output_path).open("a") as output:
                output.write(f"needs-scanning={str(needs_scanning).lower()}\n")
        logger.info("Supported image updates require scanning: %s", needs_scanning)
        raise SystemExit(0)

    comment_client = None
    if args.report_surface == "pr-comment":
        token = os.environ.get("FORGE_TOKEN")
        if not token:
            logger.error("FORGE_TOKEN is required when report-surface is pr-comment")
            raise SystemExit(1)
        comment_client = HttpForgeCommentClient(
            forge=args.forge, api_url=args.forge_api_url, token=token
        )

    scanner = GrypeScanner(cache_dir=args.scan_cache_dir)
    exit_code = run(
        event_name=event_name,
        event_path=Path(event_path_value),
        summary_path=Path(summary_path_value) if summary_path_value else None,
        scanner=scanner,
        report_surface=args.report_surface,
        comment_client=comment_client,
    )
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path and scanner.cache_updated:
        with Path(output_path).open("a") as output:
            output.write("scan-cache-updated=true\n")
    raise SystemExit(exit_code)

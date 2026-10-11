from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from renovate_vuln_report.app import run
from renovate_vuln_report.publish import HttpForgeCommentClient
from renovate_vuln_report.scan import GrypeScanner


def main() -> None:
    parser = argparse.ArgumentParser()
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
    args = parser.parse_args()

    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    event_path_value = os.environ.get("GITHUB_EVENT_PATH")
    summary_path_value = os.environ.get("GITHUB_STEP_SUMMARY")
    if not event_path_value:
        print("GITHUB_EVENT_PATH is not set", file=sys.stderr)
        raise SystemExit(1)

    comment_client = None
    if args.report_surface == "pr-comment":
        token = os.environ.get("FORGE_TOKEN")
        if not token:
            print(
                "FORGE_TOKEN is required when report-surface is pr-comment",
                file=sys.stderr,
            )
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

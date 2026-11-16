"""Prepare the database cache key shared by reporting and warmup actions."""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime


def main() -> None:
    version = json.loads(
        subprocess.check_output(["grype", "version", "--output", "json"], text=True)
    )
    schema = version.get("supportedDbSchema")
    if type(schema) is not int or schema <= 0:
        sys.exit("Grype did not report a positive integer database schema")

    prefix = (
        "renovate-vuln-report-grype-db-v3-"
        f"{os.environ['RUNNER_OS']}-{os.environ['RUNNER_ARCH']}-schema-{schema}-"
    )
    today = datetime.now(UTC).date().isoformat()
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"prefix={prefix}\n")
        output.write(f"key={prefix}{today}\n")


if __name__ == "__main__":
    main()

# Renovate Vulnerability Report

GitHub Action and CLI that reads Renovate metadata from a pull request body and reports vulnerabilities for updated container images.

First cut scope: this reports vulnerabilities found in each **New Image Revision** from Renovate Docker datasource updates. It does **not** compare against the previous image revision and does **not** produce a vulnerability diff or SBOM diff.

## GitHub Action usage

```yaml
name: Renovate vulnerability report

on:
  pull_request:

permissions:
  contents: read

jobs:
  renovate-vuln-report:
    runs-on: ubuntu-latest
    steps:
      - name: Install Grype
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
            | sh -s -- -b /usr/local/bin v0.120.1

      # Optional: log in before scanning private registry images.
      # - uses: docker/login-action@v4
      #   with:
      #     registry: ghcr.io
      #     username: ${{ github.actor }}
      #     password: ${{ secrets.GITHUB_TOKEN }}

      - uses: acidghost/renovate-vuln-report@main
```

By default, the action writes an Image Update Vulnerability Report to the actions Step Summary.

The action installs a pinned version of `uv` using `astral-sh/setup-uv` and runs with its own `uv.lock` (`--locked --no-dev`) in an isolated environment. It does not install into your project's environment. Python is downloaded by `uv` if needed; Grype must still be installed separately.

To use `uv` already available on `PATH` (for example, on a self-hosted runner or installed by an earlier step), disable setup:

```yaml
- uses: acidghost/renovate-vuln-report@main
  with:
    setup-uv: 'false'
```

Bring a compatible `uv` version. Disabling setup does not disable locked dependency installation.

### Logging

The action logs progress to stderr at `info` level by default, or `debug` when
workflow debug logging is enabled (`RUNNER_DEBUG=1`). An explicit `log-level`
overrides this automatic choice. Set `log-level` to `debug` for manifest
classification and scan-cache diagnostics, or `warning` to hide routine progress:

```yaml
- uses: acidghost/renovate-vuln-report@main
  with:
    log-level: debug
```

Supported levels are `debug`, `info`, `warning`, `error`, and `critical`
(case-insensitive). This controls the reporting application's logs, not Grype,
third-party debug logging, or other workflow steps. Reports and exit status are
unchanged by the logging level. Debug diagnostics do not dump event payloads,
loaded registry configuration, or successful Grype JSON output. Scan failures
still log scanner error details.

### Grype database cache

Publish shared Grype database snapshots with the `grype-db-cache` action in a scheduled workflow on the **consumer repository's default branch**, not in this action's source repository. Both actions use Grype on `PATH`; neither installs it:

```yaml
name: Warm Grype database

on:
  schedule:
    - cron: '17 3 * * *'
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: grype-db-cache-warmup
  cancel-in-progress: false

jobs:
  warm-grype-db:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - name: Install Grype
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
            | sh -s -- -b /usr/local/bin v0.120.1
      - uses: acidghost/renovate-vuln-report/grype-db-cache@main
```

Commit this workflow to the default branch and optionally run it manually to seed the cache. Warmup needs neither `uv` nor Renovate metadata. On Forgejo/Gitea, put the workflow under `.forgejo/workflows/` or `.gitea/workflows/` and use your runner's supported label in place of `ubuntu-latest`.

On GitHub, scheduled runs rely on the [platform's default-branch guarantee](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule), so they do not require `github.event.repository.default_branch`. Manual and other non-scheduled runs still require that field to match the run's branch; PR runs are rejected.

Both actions use the key `renovate-vuln-report-grype-db-v3-<OS>-<ARCH>-schema-<schema>-<UTC date>` and path `${{ runner.temp }}/renovate-vuln-report-grype-db`, with the same pinned cache actions. The schema comes from `Supported DB Schema` in `grype version`; an unavailable or invalid schema fails setup. Sharing requires matching schema, runner OS/architecture, cache backend, archive path, and compression: the cache service checks an opaque cache version as well as the key. The `v3` namespace leaves earlier version-keyed and PR-private snapshots behind.

- **Warmup:** reuses today's exact hit. Otherwise, it restores an older compatible snapshot if available, runs `grype db update`, and saves today's snapshot. Update failures fail warmup.
- **Reporting:** restores today's snapshot or an older schema-compatible prefix match without refreshing it. Only a complete miss triggers a network download into a **job-local database**; download failures fail the job. Reporting never saves database snapshots.

The database is prepared before scan-cache lookup and scanning, then frozen with auto-update disabled. Grype validates age and integrity; stale or corrupt restored snapshots are not silently refreshed. Schema-changing PRs download locally until default-branch warmup uses the merged Grype version. Rebase older PRs before their old-schema snapshots become stale.

A metadata preflight skips Grype/database and scan-cache setup when there are no supported Image Update Entries (such as a Grype-only mise update), while still publishing Skipped Update Entries. Invalid or missing metadata still fails reporting. Preflight does not fetch manifests; non-image OCI artifacts are classified later.

On Forgejo, PR restore searches its private scope first, then the shared repository cache; non-PR warmup publishes to the shared scope. Independent runners' local caches are not automatically shared. GitHub's branch scope and cache eviction rules also apply.

To disable caching (for example, on Forgejo/Gitea runners without a compatible cache service, or when using a custom database), set:

```yaml
- uses: acidghost/renovate-vuln-report@main
  with:
    cache-grype-db: 'false'
```

With caching disabled, Grype uses its normal database location or your `GRYPE_DB_CACHE_DIR` override, and the cache-miss download fallback is disabled too. You must provision a valid database separately: the reporting action always disables database auto-update, even when caching is disabled. The standalone CLI retains its normal update behavior.

### Vulnerability Scan cache

By default, the action also caches successful Vulnerability Scans, including scans with no findings. Updating a PR to sync with its base branch reuses these results when the scan inputs are unchanged, while still publishing the report normally.

Results are keyed by the immutable image digest, Grype version (including its embedded Syft version), loaded Grype configuration, scanner environment, and a checksum of the validated vulnerability database. Tag-only targets are resolved by hashing the original manifest bytes and scanned by digest; moved tags trigger a new scan. This does not depend on the registry's `Docker-Content-Digest` header. Multi-platform images also respect Grype's configured platform and the runner architecture. Failed scans and unsupported targets are not cached. Unresolved tags, invalid cache entries, and cache I/O failures fall back to normal scanning.

Scan caching requires `cache-grype-db: 'true'` so the database cannot change between cache lookup and scanning. A refreshed database invalidates previous results. Only vulnerability matches are stored, not Grype's configuration/registry credentials or rendered reports. Scan caching runs only for PR events, and archive keys include the PR number so results cannot be restored across PRs. Treat cached results as repository data: the Forge's cache visibility, scope, and eviction rules apply. New snapshots are saved only when new results are added, including successful scans from a partially failed report.

To disable scan caching while retaining the database cache:

```yaml
- uses: acidghost/renovate-vuln-report@main
  with:
    cache-scans: 'false'
```

Disabling `cache-grype-db` also disables action-managed scan caching. On Forgejo/Gitea, both caches require a compatible cache service.

### Pull request comments for Forgejo/Gitea

Forgejo and Gitea may expose `GITHUB_STEP_SUMMARY` only in job output, not in the pull request UI. Use `report-surface: pr-comment` to publish a Managed Pull Request Comment instead:

```yaml
permissions:
  contents: read
  issues: write

steps:
  - name: Install Grype
    run: |
      curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sh -s -- -b /usr/local/bin v0.120.1
  - uses: acidghost/renovate-vuln-report@main
    with:
      report-surface: pr-comment
      forge: forgejo # or gitea / github
      forge-api-url: ${{ github.api_url }}
      token: ${{ github.token }}
```

Comment mode uses regular issue comments on the pull request conversation and updates one managed comment identified by a hidden marker. The token must be able to list, create, and update pull request comments. Summary mode does not require write permissions.

## Required Renovate configuration

Configure Renovate to emit one machine-readable metadata note per update entry in the PR body.

Recommended: extend this repository's Renovate Metadata Preset:

```json
{
  "extends": ["github>acidghost/renovate-vuln-report"]
}
```

Or copy the configuration inline:

```json
{
  "prBodyNotes": [
    "<!-- renovate:metadata={{{encodeBase64 (toJSON (toObject 'depName' depName 'packageName' packageName 'manager' manager 'datasource' datasource 'updateType' updateType 'currentValue' currentValue 'newValue' newValue 'currentDigest' currentDigest 'newDigest' newDigest))}}} -->"
  ]
}
```

If no Renovate metadata notes are found, the action fails because it cannot know what Renovate updated.

## CLI

After installing the package, run:

```sh
renovate-vuln-report
```

The CLI expects actions environment variables:

- `GITHUB_EVENT_NAME` must be `pull_request`
- `GITHUB_EVENT_PATH` must point to the pull request event payload
- `GITHUB_STEP_SUMMARY`, when summary mode is used, receives the markdown report

Options:

- `--log-level debug|info|warning|error|critical` defaults to `debug` when `RUNNER_DEBUG=1`, otherwise `info` (case-insensitive)
- `--report-surface summary|pr-comment` defaults to `summary`
- `--forge github|forgejo|gitea` defaults to `github`
- `--forge-api-url URL` defaults to `GITHUB_API_URL`, then `https://api.github.com`
- `--scan-cache-dir PATH` enables local scan caching; requires a prepared, valid Grype database and `GRYPE_DB_AUTO_UPDATE=false`. Refresh the database with `grype db update` before running. Otherwise, scans bypass the cache.
- `--preflight` is used by the action to append `needs-scanning=true|false` to `GITHUB_OUTPUT` without invoking Grype or publishing. It defers invalid metadata to the subsequent normal reporting run, which publishes the error and fails.

Environment variables:

- `RENOVATE_VULN_REPORT_LOG_LEVEL` sets the default log level; a nonempty value overrides `RUNNER_DEBUG`, and `--log-level` takes precedence
- `RENOVATE_VULN_REPORT_SURFACE` can set the default report surface
- `RENOVATE_VULN_REPORT_FORGE` can set the default forge
- `RENOVATE_VULN_REPORT_SCAN_CACHE_DIR` can set the scan cache directory; caching is disabled by default in the CLI
- `FORGE_TOKEN` is required when `--report-surface pr-comment` is used
- `GRYPE_CHECK_FOR_APP_UPDATE` defaults to `false` for Grype subprocesses; set it to `true` to enable Grype's startup version check when using the CLI.

`grype` must already be installed and available on `PATH`. Registry credentials, when needed, must be prepared before running the CLI.

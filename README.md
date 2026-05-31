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
      - uses: actions/setup-python@v6
        with:
          python-version: '3.14'

      - name: Install Grype
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
            | sh -s -- -b /usr/local/bin

      # Optional: log in before scanning private registry images.
      # - uses: docker/login-action@v4
      #   with:
      #     registry: ghcr.io
      #     username: ${{ github.actor }}
      #     password: ${{ secrets.GITHUB_TOKEN }}

      - uses: acidghost/renovate-vuln-report@main
```

By default, the action writes an Image Update Vulnerability Report to the actions Step Summary.

### Pull request comments for Forgejo/Gitea

Forgejo and Gitea may expose `GITHUB_STEP_SUMMARY` only in job output, not in the pull request UI. Use `report-surface: pr-comment` to publish a Managed Pull Request Comment instead:

```yaml
permissions:
  contents: read
  issues: write

steps:
  - uses: actions/setup-python@v6
    with:
      python-version: '3.14'
  - name: Install Grype
    run: |
      curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sh -s -- -b /usr/local/bin
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

- `--report-surface summary|pr-comment` defaults to `summary`
- `--forge github|forgejo|gitea` defaults to `github`
- `--forge-api-url URL` defaults to `GITHUB_API_URL`, then `https://api.github.com`

Environment variables:

- `RENOVATE_VULN_REPORT_SURFACE` can set the default report surface
- `RENOVATE_VULN_REPORT_FORGE` can set the default forge
- `FORGE_TOKEN` is required when `--report-surface pr-comment` is used

`grype` must already be installed and available on `PATH`. Registry credentials, when needed, must be prepared before running the CLI.

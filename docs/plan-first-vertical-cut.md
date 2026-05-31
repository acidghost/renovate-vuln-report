# First Vertical Cut Plan

Build a minimal GitHub Action and CLI that produces an Image Update Vulnerability Report for Renovate pull requests.

## Scope

Included:

- Read the GitHub `pull_request` event payload.
- Parse Renovate Metadata Notes from the pull request body.
- Decode each Renovate Metadata Payload into one Update Entry.
- Support Image Update Entries identified by Renovate's Docker datasource.
- Build Scan Targets from New Image Revisions only.
- Run Grype directly against registry image references.
- Consume Grype JSON output.
- Publish an Image Update Vulnerability Report to the GitHub Actions Step Summary.
- Expose a minimal user-facing CLI named `renovate-vuln-report`.
- Package the GitHub Action as a composite action that invokes the CLI.

Out of scope:

- Vulnerability Diff between Current Image Revision and New Image Revision.
- PURL scanning.
- SBOM generation, scanning, storage, or diffing.
- PR comments, check annotations, or persistent report updates.
- Policy enforcement such as failing on severity, KEV, or EPSS thresholds.
- Installing Grype.
- Managing registry credentials.
- User-configurable Scan Target Platform.
- Supporting `pull_request_target` or PR body override inputs.

## Inputs and preconditions

- The workflow must run on a `pull_request` event.
- The pull request body must be available in the event payload.
- The pull request body must contain at least one valid Renovate Metadata Note.
- `grype` must already be installed and available on `PATH`.
- Registry authentication, when needed, must already be available in the environment.

## Renovate metadata contract

Each Renovate Metadata Note represents exactly one Update Entry.

For the first cut, the expected metadata fields are:

- `depName`
- `packageName`
- `manager`
- `datasource`
- `updateType`
- `currentValue`
- `newValue`
- `currentDigest`
- `newDigest`

Image Update Entries are selected when Renovate identifies the dependency source as Docker.

The Image Repository is derived from `packageName` when present, otherwise `depName`.

A New Image Revision is formed from the Image Repository plus `newValue`, `newDigest`, or both. When both tag and digest are available, keep both: `repository:tag@digest`.

## Grype invocation

For each distinct Scan Target, invoke Grype against the registry source:

```sh
grype -o json registry:<image-reference>
```

Do not specify a Scan Target Platform in the first cut; allow Grype to use its default.

Deduplicate Vulnerability Scans by exact normalized Scan Target identity. The Grype `registry:` source prefix is not part of the domain identity.

## Report shape

The Step Summary should group findings by Scan Target, nested under or clearly associated with the relevant Image Update Entry.

For each Scan Target, show:

- Scan Target identity
- total finding counts by severity
- top 20 Vulnerability Findings
- a note when additional findings are omitted

Each shown Vulnerability Finding should include:

- severity
- vulnerability ID
- Affected Package name
- installed version
- fixed version or versions, when available
- EPSS, when available
- KEV marker, when available

Sort findings within each Scan Target by:

1. KEV findings first
2. higher EPSS first when available
3. severity: Critical, High, Medium, Low, Negligible, Unknown
4. vulnerability ID as a stable tie-breaker

The Step Summary should include a Skipped Update Entry section listing Unsupported Update Entries and skip reasons.

For failed Vulnerability Scans, include a sanitized failure reason and the Scan Target identity in the Step Summary. Put fuller diagnostics in the action log, not the summary.

## Success and failure behavior

- Not a `pull_request` event: fail.
- Pull request body unavailable: fail.
- No Renovate Metadata Notes: fail.
- Any Renovate Metadata Note malformed: fail.
- Metadata notes valid, but zero supported Scan Targets: succeed with a Step Summary.
- Some Unsupported Update Entries: succeed if all supported Scan Targets scan successfully.
- Any supported Vulnerability Scan fails: fail after writing a partial Step Summary.
- Vulnerabilities found: succeed by default.
- No vulnerabilities found: succeed.

## Test strategy

Implement the first cut test-first, starting with unit tests for:

1. Renovate Metadata Note extraction and decoding.
2. Renovate Metadata Payload interpretation into Update Entries.
3. Image Revision construction.
4. Success and failure behavior.
5. Grype JSON mapping into Vulnerability Findings.
6. Step Summary rendering.

## Packaging

- Rename the Python project to `renovate-vuln-report`.
- Rename the Python package to `renovate_vuln_report`.
- Expose the CLI command as `renovate-vuln-report`.
- Create a composite GitHub Action named `Renovate Vulnerability Report` that invokes the CLI.

## Renovate Metadata Preset

Publish a repository-hosted default preset in `default.json` so users can configure Renovate with:

```json
{
  "extends": ["github>acidghost/renovate-vuln-report"]
}
```

The preset emits the required Renovate Metadata Note through `prBodyNotes`.

## Documentation

The README should include:

- Example workflow using the composite action.
- A prior step that installs Grype.
- A prior step for registry login when private images are scanned.
- Required Renovate Metadata Preset usage and inline `prBodyNotes` configuration.
- Clear statement that the first cut reports New Image Revision vulnerabilities only and does not produce a diff.

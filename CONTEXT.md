# Renovate SBOM Diff

This context describes how Renovate dependency updates are interpreted so vulnerability information can be reported for the updated dependencies.

The repository name is provisional and should not be treated as authoritative domain language. The user-facing command name is `renovate-vuln-report`.

## Language

**Renovate PR**:
A pull request created by Renovate to update one or more dependencies. A Renovate PR contains one or more **Update Entries**.

**Update Entry**:
The atomic dependency update described by Renovate metadata: one dependency moving from a current version or digest to a new version or digest. A Renovate PR may contain multiple Update Entries.
_Avoid_: Dependency, update, PR item

**Unsupported Update Entry**:
An **Update Entry** that cannot be analyzed because it is outside the supported scope or lacks the information needed to form a **Scan Target**. Unsupported Update Entries are skipped rather than treated as failed scans.
_Avoid_: Invalid dependency, scan failure, bad update

**Skipped Update Entry**:
An **Unsupported Update Entry** recorded in a **Vulnerability Report** as not scanned, along with the reason it was skipped.
_Avoid_: Ignored update, excluded dependency

**Renovate Metadata Note**:
A machine-readable HTML comment embedded in a Renovate PR body that contains a **Renovate Metadata Payload** for exactly one **Update Entry**. A Renovate PR with multiple Update Entries should contain multiple Renovate Metadata Notes.
_Avoid_: Comment, note, metadata

**Renovate Metadata Payload**:
The decoded Renovate-shaped data from one **Renovate Metadata Note**. A Renovate Metadata Payload is interpreted into an **Update Entry**.
_Avoid_: Metadata, JSON, note contents

**Renovate Metadata Preset**:
Reusable Renovate configuration that emits one **Renovate Metadata Note** per **Update Entry**.
_Avoid_: Config snippet, prBodyNotes snippet, Renovate config

**Image Update Entry**:
An **Update Entry** where the updated dependency is a container image reference. It has a **Current Image Revision** and a **New Image Revision**. A Renovate Metadata Payload represents an Image Update Entry when Renovate identifies the dependency source as Docker.
_Avoid_: Docker update, container update

**Image Repository**:
The registry and repository name of a container image, without the revision selector. For Renovate metadata, the Image Repository is taken from `packageName` when present, otherwise from `depName`.
_Avoid_: Dependency name, package name, image name

**Image Revision**:
A container image identified by an **Image Repository** and at least one revision selector, such as a tag, digest, or both. When both tag and digest are available, the digest identifies the image immutably and the tag preserves human context.
_Avoid_: Image candidate, image version, target image

**Current Image Revision**:
The **Image Revision** before a Renovate update.
_Avoid_: Old image, previous image, current candidate

**New Image Revision**:
The **Image Revision** after a Renovate update and the initial **Scan Target** for the first vertical cut.
_Avoid_: Updated image, target image, new candidate

**Scan Target**:
A supported revision or artifact selected for vulnerability scanning. For the first vertical cut, every Scan Target is a **New Image Revision** from an **Image Update Entry**.
_Avoid_: Scan subject, target image

**Scan Target Platform**:
The operating-system and architecture variant used when scanning a multi-platform image. The first vertical cut leaves the Scan Target Platform unspecified and may allow users to set it later.
_Avoid_: Scan Platform, host platform, architecture, Grype platform

**Vulnerability Scan**:
One assessment of one **Scan Target** for known vulnerabilities. A Vulnerability Scan may succeed or fail. Finding vulnerabilities is a successful scan outcome, not a scan failure.
_Avoid_: Grype run, scan result

**Vulnerability Finding**:
One reported vulnerability affecting an **Affected Package** within a **Scan Target**. A Vulnerability Finding may include exploit-prioritization signals such as **EPSS** and **KEV** when available.
_Avoid_: Vulnerability, scanner match, issue

**EPSS**:
The Exploit Prediction Scoring System signal associated with a **Vulnerability Finding**, used to indicate likelihood of exploitation when available.
_Avoid_: Exploit score, risk score

**KEV**:
The Known Exploited Vulnerabilities signal associated with a **Vulnerability Finding**, used to indicate that the vulnerability is known to be exploited when available.
_Avoid_: Exploited flag, known exploited marker

**Affected Package**:
A package within a **Scan Target** that a **Vulnerability Finding** applies to.
_Avoid_: Dependency, component, artifact

**Vulnerability Report**:
A listing of vulnerabilities found for one or more scanned revisions. A Vulnerability Report does not imply comparison with a previous revision and may be partial when some Vulnerability Scans fail. For the first vertical cut, findings are grouped by **Scan Target** and published as a **Step Summary**.
_Avoid_: Diff, SBOM diff, vulnerability diff

**Image Update Vulnerability Report**:
A **Vulnerability Report** for **New Image Revisions** from **Image Update Entries** in a **Renovate PR**.
_Avoid_: Container image vulnerability report, SBOM diff, image diff

**Step Summary**:
The GitHub Actions job summary used as the first report surface for the **Vulnerability Report**.
_Avoid_: PR comment, action log, check annotation

**Vulnerability Diff**:
A comparison of vulnerabilities between two revisions that identifies changes such as introduced, fixed, or unchanged vulnerabilities. A Vulnerability Diff is out of scope for the first vertical cut.
_Avoid_: Report, scan results

## Example dialogue

Dev: "Does this action scan the whole Renovate PR as one thing?"
Domain expert: "No. The Renovate PR is just the carrier; each Update Entry is analyzed separately."
Dev: "For image updates, do we scan the whole update?"
Domain expert: "For the first cut, we scan the New Image Revision from each Image Update Entry. The Current Image Revision remains available for future comparison."
Dev: "Should the first output be called a diff?"
Domain expert: "No. If only the New Image Revision is scanned, the output is a Vulnerability Report. A Vulnerability Diff requires comparing revisions."
Dev: "How many updates does a Renovate Metadata Note describe?"
Domain expert: "Exactly one Update Entry. If a Renovate PR has multiple Update Entries, it should carry multiple Renovate Metadata Notes."
Dev: "For an image update, which Renovate field names the image repository?"
Domain expert: "Use `packageName` when present, otherwise `depName`. `depName` is allowed as a fallback, not as the preferred canonical name."
Dev: "If Renovate gives both a tag and a digest, which one defines the Image Revision?"
Domain expert: "Use both. The digest gives the immutable identity; the tag keeps the report understandable to humans."
Dev: "What does Grype scan?"
Domain expert: "It scans a Scan Target. In the first cut, each Scan Target is a New Image Revision."
Dev: "If one Scan Target fails, should the whole report disappear?"
Domain expert: "No. Report successful scans, but treat the failed Vulnerability Scan as a failed action outcome."
Dev: "Should vulnerabilities fail the action?"
Domain expert: "Not by default. Finding vulnerabilities is a successful Vulnerability Scan; the first cut reports findings without enforcing a policy."
Dev: "Where should the first Vulnerability Report appear?"
Domain expert: "In the GitHub Actions Step Summary. It avoids PR comment noise and does not require PR write permissions."
Dev: "Which platform should the first scan use for multi-platform images?"
Domain expert: "Do not specify a Scan Target Platform in the first cut. Let the scanner use its default, and consider a user-set Scan Target Platform later."

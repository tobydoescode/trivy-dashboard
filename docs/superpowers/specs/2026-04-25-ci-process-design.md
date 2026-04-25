# Improved CI Process Design

## Goal

Build a CI process that gives useful feedback on pull requests, avoids duplicate work on ordinary branch pushes, and only publishes container images after source tests, security checks, image smoke tests, and image vulnerability scans have passed.

## Event Policy

CI should run for these events:

- `pull_request`: run full validation when a PR is opened, reopened, marked ready for review, or updated with new commits.
- `push` to `main`: run full validation, then publish the image if validation passes.
- `push` tags matching `v*`: run full validation, then publish versioned image tags if validation passes.
- `workflow_dispatch`: allow manual full validation/publish behavior using the same gates as push events.

CI should not run full validation on ordinary non-main branch pushes. Those pushes are validated once a PR exists, avoiding duplicate runs for every local branch update.

Fork PRs must be supported. Jobs that only read source code and build local artifacts can run on fork PRs. Jobs or steps that require write permissions, secrets, package publishing, SARIF upload, or PR comments must be guarded so they do not fail or expose privileged tokens on fork PRs.

The repository's GitHub Actions settings are part of the CI design. Before implementing the workflow, check the repository setting for fork pull request approvals:

- preferred: require approval for all external contributors;
- acceptable: require approval for first-time contributors;
- not preferred: automatically run workflows for all external fork PRs.

This setting is not represented in workflow YAML, so the implementation plan should include an explicit setup verification step in the GitHub repository settings.

## Proposed File Structure

```text
.github/
├── actions/
│   ├── test/
│   │   └── action.yaml          # Go/JS tests, coverage, and test artifacts
│   ├── source-security/
│   │   └── action.yaml          # govulncheck and optional secret scanning
│   ├── image-smoke/
│   │   └── action.yaml          # run envtest-backed smoke test against local image
│   └── image-security/
│       └── action.yaml          # Trivy image scan and report generation
└── workflows/
    └── ci.yaml                  # orchestration, job graph, permissions, publishing

internal/
└── smoke/
    ├── image_smoke_test.go     # build-tagged envtest-backed image smoke test
    └── trivy_crd.go            # minimal VulnerabilityReport CRD fixture for envtest

scripts/
└── docker-build-needed.sh      # existing image relevance detector
```

The existing `.github/workflows/build-image.yaml` should be replaced by a single broader CI workflow, either by renaming it to `ci.yaml` or by keeping the filename and changing its contents. A single workflow is preferred because job dependencies, `changes.outputs.build-needed`, event context, and publish gates remain explicit in one place. Job-level permissions still keep package publishing privileges away from routine PR validation.

Verbose validation steps should live in local composite actions under `.github/actions/`. The workflow remains the single orchestration layer; composite actions keep command/reporting details readable without introducing cross-workflow `workflow_call` indirection.

Keep Docker publish and manifest creation directly in `ci.yaml` initially. Publishing is tightly coupled to event conditions, job permissions, GHCR login, digest artifacts, and manifest tags, so hiding it inside a composite action would make the release gate harder to audit.

## Workflow Responsibilities

### `.github/workflows/ci.yaml`

Runs on:

```yaml
on:
  pull_request:
  push:
    branches: [main]
    tags: ["v*"]
  workflow_dispatch:
```

Top-level permissions should be minimal:

```yaml
permissions:
  contents: read
```

Jobs:

- `changes`
  - Reuses `scripts/docker-build-needed.sh`.
  - Outputs `build-needed=true|false`.
  - Treats tags and manual runs as image-relevant.

- `test`
  - Runs on all supported events.
  - Uses `actions/setup-go` with `go-version-file: go.mod`.
  - Uses `actions/setup-node` for the JS smoke tests.
  - Calls `./.github/actions/test`.
  - Runs Go tests with coverage.
  - Runs `go vet ./...`.
  - Runs `node --test internal/views/static/app.test.mjs`.
  - Produces:
    - Go JUnit XML.
    - `coverage.out`.
    - `coverage.html`.
    - JS TAP output.
    - GitHub job summary with total Go coverage.
  - Uploads reports as workflow artifacts.
  - Publishes test result annotations where permissions allow it.

- `source-security`
  - Runs on all supported events.
  - Calls `./.github/actions/source-security`.
  - Runs `govulncheck ./...`.
  - Optionally runs a secret scan, either via existing pre-commit/gitleaks tooling or a dedicated action.
  - Uploads logs/reports as artifacts.

- `image-validation`
  - Runs only when `changes.outputs.build-needed == 'true'`.
  - Depends on `changes`, `test`, and `source-security`.
  - Runs automatically for trusted PR authors and all trusted push/tag/manual events.
  - For untrusted fork PRs, either rely on repository-level approval before the workflow starts or require an explicit maintainer-controlled label before running this job.
  - Builds a local `linux/amd64` smoke image with `load: true`.
  - Tags the image as `trivy-dashboard:smoke`.
  - Does not push.
  - Calls `./.github/actions/image-smoke` against `trivy-dashboard:smoke`.
  - Calls `./.github/actions/image-security` against `trivy-dashboard:smoke`.
  - The smoke action runs `go test -tags image_smoke ./internal/smoke -v`.
  - The smoke test starts envtest, installs the Trivy `VulnerabilityReport` CRD, creates at least one fixture report, starts the built container, and verifies HTTP output.
  - The security action runs Trivy against the local image before any publish.
  - Blocks on image smoke failures and `CRITICAL,HIGH` image vulnerabilities.
  - Produces:
    - image smoke logs;
    - SARIF report.
    - JSON report.
    - human-readable table or Markdown summary.
  - Uploads reports as artifacts.
  - Uploads SARIF only when the event/context has `security-events: write`.

- `build`
  - Existing matrix build for `linux/amd64` and `linux/arm64`.
  - Uses `push-by-digest=true`.
  - Depends on `changes`, `test`, `source-security`, and `image-validation`.
  - Runs only when:
    - the event is not `pull_request`;
    - `changes.outputs.build-needed == 'true'`;
    - prior validation jobs passed.
  - Requires `packages: write`, scoped to this job only.
  - Publishes per-platform image digests to GHCR.

- `merge`
  - Existing manifest-list creation.
  - Depends on `build`.
  - Runs only when `build` succeeds.
  - Pushes branch, semver, SHA, and `latest` tags according to current metadata rules.

The core dependency graph should be:

```text
changes

test ───────────────┐
source-security ────┼── image-validation ── build ── merge
                    └───────────────────────┘
```

`image-validation`, `build`, and `merge` are skipped when `build-needed` is false. In that case no Docker build input changed, so there is no new image content to validate or publish. Source validation still runs for README-only or configuration-only changes so PRs continue to prove the repository is healthy without doing unnecessary image work.

The local smoke image build, image smoke test, and image vulnerability scan intentionally run in one job because GitHub Actions jobs do not share Docker daemon state across runners. Keeping them together avoids `docker save`/`docker load` artifact plumbing and ensures both checks run against the exact same local image.

## PR Trust Policy

Use GitHub's repository-level fork approval settings as the primary control for whether workflows from external contributors start automatically.

Within workflow YAML, distinguish trusted and untrusted contexts for expensive or privileged behavior:

Trusted PR authors:

- `OWNER`
- `MEMBER`
- `COLLABORATOR`

Potentially untrusted PR authors:

- `CONTRIBUTOR`
- `FIRST_TIME_CONTRIBUTOR`
- `FIRST_TIMER`
- `NONE`

Fork PR detection:

```yaml
github.event_name == 'pull_request' &&
github.event.pull_request.head.repo.full_name != github.repository
```

Trusted-author check:

```yaml
contains(
  fromJSON('["OWNER","MEMBER","COLLABORATOR"]'),
  github.event.pull_request.author_association
)
```

Recommended behavior:

- Always run lightweight read-only validation once the PR workflow is approved by GitHub: tests, coverage, `go vet`, JS tests, and `govulncheck`.
- Run image validation automatically for trusted authors.
- For untrusted fork PRs, either:
  - rely on "require approval for all external contributors" so maintainers explicitly approve the whole workflow before it starts; or
  - gate `image-validation` behind a maintainer-applied label such as `run-image-ci`.
- Never run package publishing on pull requests.
- Never use `pull_request_target` for workflows that check out and execute PR code.

If label-gating is used, the workflow condition should be explicit:

```yaml
if: >
  needs.changes.outputs.build-needed == 'true' &&
  (
    github.event_name != 'pull_request' ||
    contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.pull_request.author_association) ||
    contains(github.event.pull_request.labels.*.name, 'run-image-ci')
  )
```

The simpler preferred policy is repository-level approval for all external contributors plus workflow-level guards only for write-sensitive steps.

## Composite Action Responsibilities

### `.github/actions/test/action.yaml`

Inputs:

- none initially.

Responsibilities:

- install `gotestsum`;
- run Go tests with coverage;
- generate `go-test-results.xml`;
- generate `coverage.out`;
- generate `coverage.html`;
- run `go vet ./...`;
- run JS tests and write `js-test-results.tap`;
- append test and coverage summary to `$GITHUB_STEP_SUMMARY`;
- upload test and coverage artifacts.

The parent job remains responsible for checkout, Go setup, Node setup, permissions, and any PR comment permissions.

### `.github/actions/source-security/action.yaml`

Inputs:

- none initially.

Responsibilities:

- install and run `govulncheck ./...`;
- optionally run Gitleaks against the checked-out repository;
- write a security summary to `$GITHUB_STEP_SUMMARY`;
- upload security reports as artifacts.

If Gitleaks requires different fork behavior, gate that step in the parent workflow or expose a boolean input such as `run-secret-scan`.

### `.github/actions/image-smoke/action.yaml`

Inputs:

- `image-ref`, defaulting to `trivy-dashboard:smoke`.

Responsibilities:

- run `go test -tags image_smoke ./internal/smoke -v`;
- pass the image reference to the smoke test via `TRIVY_DASHBOARD_SMOKE_IMAGE`;
- upload smoke logs on failure;
- write smoke result summary to `$GITHUB_STEP_SUMMARY`.

The parent job remains responsible for building the local image with `load: true`.

### `.github/actions/image-security/action.yaml`

Inputs:

- `image-ref`, defaulting to `trivy-dashboard:smoke`;
- `severity`, defaulting to `CRITICAL,HIGH`;
- `exit-code`, defaulting to `1`.

Responsibilities:

- run Trivy against the local image;
- produce SARIF, JSON, and table/Markdown reports;
- upload raw reports as artifacts;
- write a vulnerability summary to `$GITHUB_STEP_SUMMARY`.

The parent workflow remains responsible for SARIF upload because that depends on event trust and `security-events: write`.

## Sharing Across Repositories

The local composite actions can later move to a shared repository if the same CI patterns are useful across multiple projects.

Local use:

```yaml
- uses: ./.github/actions/test
```

Shared-repo use:

```yaml
- uses: tobydoescode/github-actions/.github/actions/test@v1
```

To make that migration easy:

- keep composite action inputs explicit and stable;
- avoid hard-coding this repository name inside action logic;
- pass image names, test package paths, and severity policies as inputs when they vary;
- keep repository-specific orchestration in `ci.yaml`;
- version shared actions with tags such as `v1`.

Do not move publishing orchestration to a shared action initially. Different repositories tend to have different image names, registries, tag policies, environments, and permissions, so publishing should stay local until there is a clear repeated pattern.

## Image Smoke Test Design

The image smoke test should prove the built image works against a Kubernetes-like API, not just that Docker can build it.

Test flow:

1. Start `envtest` Kubernetes API server and etcd.
2. Install a minimal `vulnerabilityreports.aquasecurity.github.io/v1alpha1` CRD.
3. Create namespace `web`.
4. Create a fixture `VulnerabilityReport` with:
   - namespace: `web`
   - workload: `nginx-abc`
   - image: `library/nginx:1.25`
   - one critical vulnerability: `CVE-2024-0001`
5. Write an envtest kubeconfig to a temp file.
6. Run the built image with:
   - `--network host` on GitHub Linux runners;
   - `TRIVY_DASHBOARD_ADDR=:18080`;
   - `KUBECONFIG=/tmp/kubeconfig`;
   - the kubeconfig mounted read-only.
7. Wait for `/healthz` to return `200`.
8. Wait for `/readyz` to return `200`.
9. Fetch `/api/dashboard` and assert it contains:
   - `web/nginx-abc`
   - `library/nginx:1.25`
   - `1 Critical`
   - `rag-red`
10. Fetch `/workload/web/nginx-abc` and assert it contains:
   - `CVE-2024-0001`
   - `CRITICAL`
   - `libcurl`

This verifies the image can start, load embedded templates/static assets, connect to a Kubernetes API, list/watch the CRD, parse reports, mark readiness, and render real dashboard HTML.

## Report Outputs

Each CI run should preserve enough evidence for review and debugging.

Artifacts:

- `go-test-results.xml`
- `coverage.out`
- `coverage.html`
- `js-test-results.tap`
- `govulncheck` output
- Trivy SARIF/JSON/table reports
- image smoke logs on failure

Job summary:

- test result summary;
- total Go coverage;
- JS smoke test pass/fail;
- source security result;
- image smoke result when run;
- image vulnerability summary when run.

PR comments:

- Optional, only for same-repository PRs where `pull-requests: write` is safe.
- Prefer a sticky comment containing coverage and scan summary.
- Fork PRs should rely on artifacts and job summaries instead of comments.

## Security Policy

Blocking:

- Go tests fail.
- `go vet` fails.
- JS smoke tests fail.
- `govulncheck` reports reachable vulnerabilities.
- Image smoke test fails when image-relevant files changed.
- Trivy finds `CRITICAL` or `HIGH` vulnerabilities in the local image.

Non-blocking initially:

- Medium/low image vulnerabilities.
- Coverage threshold enforcement.
- PR comment publishing.

Coverage should be reported first, not enforced. A minimum threshold can be added later once the baseline is stable.

## Repository Setup Checks

Before implementation is considered complete, verify these repository settings in GitHub:

- Actions are enabled for the repository.
- Fork pull request workflows require approval from maintainers, preferably for all external contributors.
- The workflow token default permission is read-only unless a job explicitly requests broader permissions.
- GHCR package publishing works with `GITHUB_TOKEN` from the `main` branch workflow.
- Code scanning/SARIF upload is enabled or at least accepted for trusted contexts.
- Branch protection, if enabled, requires the new CI workflow checks before merging to `main`.

## Permissions

Use job-level permissions instead of broad workflow-level permissions.

Default:

```yaml
permissions:
  contents: read
```

For SARIF upload:

```yaml
permissions:
  contents: read
  security-events: write
```

Guard this to trusted contexts only if fork PRs cannot upload SARIF.

For PR comments:

```yaml
permissions:
  contents: read
  pull-requests: write
```

Only run PR comment steps for same-repo PRs:

```yaml
if: github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository
```

For package publishing:

```yaml
permissions:
  contents: read
  packages: write
```

Only publishing jobs should have `packages: write`.

## Open Decisions

- Whether to name the single workflow `.github/workflows/ci.yaml` or keep the existing `.github/workflows/build-image.yaml` filename. Preferred: rename to `ci.yaml` because the workflow will cover more than image builds.
- Whether local composite actions should be promoted to a shared repository later. Preferred: start local, extract only after another repository needs the same behavior.
- Whether Trivy SARIF upload should run for fork PRs. Preferred: upload SARIF only in trusted contexts, always upload raw artifacts.
- Whether to add a coverage threshold. Preferred: report only for now.
- Whether to scan secrets with Gitleaks in CI in addition to the existing pre-commit hook. Preferred: yes, because pre-commit hooks are advisory and local.

## Acceptance Criteria

- PR creation and PR branch updates run tests, coverage, source security, and image checks when relevant.
- Ordinary non-main branch pushes do not run duplicate full CI.
- Pushes to `main` run validation before image publishing.
- Images are not published unless source tests, source security, image smoke, and image security pass.
- Fork PRs can run read-only validation without requiring secrets or write permissions.
- Test, coverage, smoke, and security reports are available as artifacts.
- The built image is tested against envtest with a real fixture `VulnerabilityReport` before publish.

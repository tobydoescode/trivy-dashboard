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

## Proposed File Structure

```text
.github/
└── workflows/
    ├── ci.yaml                 # PR/main validation: tests, reports, security, image smoke/scan
    └── build-image.yaml        # Main/tag image publishing only, gated by ci.yaml-equivalent jobs

internal/
└── smoke/
    ├── image_smoke_test.go     # build-tagged envtest-backed image smoke test
    └── trivy_crd.go            # minimal VulnerabilityReport CRD fixture for envtest

scripts/
├── docker-build-needed.sh      # existing image relevance detector
└── coverage-summary.sh         # optional helper to produce Markdown coverage summary
```

Alternative: keep a single workflow file and add jobs to the existing `build-image.yaml`. Splitting is preferred because it makes the validation pipeline and publishing pipeline easier to read and keeps package-write permissions away from routine PR validation.

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
  - Runs `govulncheck ./...`.
  - Optionally runs a secret scan, either via existing pre-commit/gitleaks tooling or a dedicated action.
  - Uploads logs/reports as artifacts.

- `image-smoke`
  - Runs only when `changes.outputs.build-needed == 'true'`.
  - Builds a local `linux/amd64` smoke image with `load: true`.
  - Runs `go test -tags image_smoke ./internal/smoke -v`.
  - The smoke test starts envtest, installs the Trivy `VulnerabilityReport` CRD, creates at least one fixture report, starts the built container, and verifies HTTP output.
  - Uploads container logs and smoke test output on failure.

- `image-security`
  - Runs only when `changes.outputs.build-needed == 'true'`.
  - Uses the same local smoke image tag pattern as `image-smoke`, or rebuilds the local image if job isolation makes sharing impractical.
  - Runs Trivy against the local image before any publish.
  - Blocks on `CRITICAL,HIGH` findings.
  - Produces:
    - SARIF report.
    - JSON report.
    - human-readable table or Markdown summary.
  - Uploads reports as artifacts.
  - Uploads SARIF only when the event/context has `security-events: write`.

### `.github/workflows/build-image.yaml`

Runs on:

```yaml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
```

Publishing should only happen when:

- the CI workflow concluded successfully;
- the original event was `push` to `main`, a `v*` tag, or approved manual dispatch behavior;
- image-relevant files changed, or the event is a tag/manual publish.

If `workflow_run` makes event/original-ref handling too awkward, keep publishing jobs in `ci.yaml` instead. The important design requirement is that publishing jobs depend on `test`, `source-security`, `image-smoke`, and `image-security`.

Publishing jobs:

- `build`
  - Existing matrix build for `linux/amd64` and `linux/arm64`.
  - Uses `push-by-digest=true`.
  - Requires `packages: write`, scoped to this job only.
  - Does not run on pull requests.

- `merge`
  - Existing manifest-list creation.
  - Depends on `build`.
  - Pushes branch, semver, SHA, and `latest` tags according to current metadata rules.

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

- Whether to keep one workflow file or split validation and publishing. Preferred: split if `workflow_run` gating is manageable; otherwise keep one file with clear job boundaries.
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

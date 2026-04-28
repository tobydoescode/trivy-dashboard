# Trivy Dashboard

In-cluster Go web dashboard that renders Trivy Operator `VulnerabilityReport`
CRDs as Red/Amber/Green vulnerability summaries and per-workload detail views.

No database. No polling. Dynamic informer watches reports cluster-wide, caches
in memory, renders server-side HTML. SSE pushes live updates to browsers.

## 0. Project

### Quick Reference

[Task](https://taskfile.dev) is the task runner. Run `task --list-all` to see available commands.

Run locally: `task run` (needs `KUBECONFIG`). Run tests: `task test`. Coverage: `task test:cover`.

### Tech Stack

- **Go** — stdlib `net/http` (1.22+ path patterns, no router library)
- **Kubernetes** — `client-go` dynamic informers, `controller-runtime/envtest` for smoke tests
- **Frontend** — vanilla JS, `html/template`, embedded via `//go:embed`
- **Observability** — `log/slog` (JSON), Prometheus client
- **Container** — distroless nonroot (UID 65532), multi-arch (amd64/arm64)

### Project Layout

```
main.go                     Entry point: config, k8s client, informer, routes, server
internal/
  api/                      HTTP handlers, view models, SSE broker, security headers
  auth/                     Bearer token middleware (constant-time compare)
  kube/                     Domain types, CRD parser, thread-safe in-memory store
  metrics/                  Prometheus metrics registration
  smoke/                    Build-tagged (image_smoke) integration tests using envtest
  views/
    views.go                go:embed directives
    templates/              index.html, dashboard.html, workload-detail.html
    static/                 app.js, style.css
    static_test/            Node.js tests for app.js (node:test runner)
.github/
  workflows/ci.yaml         CI pipeline
  actions/                  Composite actions: test, source-security, image-smoke, image-security
scripts/                    Shell helpers (docker-build-needed.sh)
```

### Architecture

**Data flow**: K8s informer → parse unstructured → Store (RWMutex map) → SSE broker notifies → browser refetches HTML partial.

**Routes**:
| Path | Auth | Purpose |
|------|------|---------|
| `GET /` | no | Shell page (fetches `/api/dashboard` client-side) |
| `GET /static/*` | no | Embedded CSS/JS |
| `GET /healthz` | no | Liveness probe |
| `GET /readyz` | no | 503 until informer synced |
| `GET /metrics` | no | Prometheus |
| `POST /api/session` | bearer | Exchange token for HTTP-only session cookie |
| `GET /api/dashboard` | bearer/session | Aggregated summary HTML partial |
| `GET /workload/{ns}/{name}` | bearer/session | Detail table for one report |
| `GET /api/events` | session | SSE stream ("refresh" on store changes) |

Auth only active when `TRIVY_DASHBOARD_TOKEN` env var is set.

**RAG logic**: Red = any CRITICAL/HIGH. Amber = any MEDIUM (no higher). Green = LOW only or clean.

### Environment Variables

| Var | Default | Purpose |
|-----|---------|---------|
| `TRIVY_DASHBOARD_ADDR` | `:8080` | Listen address |
| `TRIVY_DASHBOARD_TOKEN` | unset | Enables bearer auth + session cookies |
| `TRIVY_DASHBOARD_SECURE_COOKIES` | `false` | Force `Secure` flag on cookies |
| `KUBECONFIG` | `~/.kube/config` | Outside-cluster only |

### Testing

**Go tests**: `go test ./...` — stdlib `testing`, `httptest`, table-driven tests, hand-written mocks (no mocking library).

**JS tests**: `node --test internal/views/static_test/app.test.mjs` — `node:test` runner, `vm.runInNewContext` sandbox.

**Smoke tests**: `go test -tags image_smoke ./internal/smoke` — envtest (real API server + etcd), runs container image against fixture CRD data.

**Coverage**: `task test:cover` → `.coverage/coverage.html`

### Conventions

- **Error handling**: simple and explicit. `slog.Error` + HTTP status code. `os.Exit(1)` on fatal startup errors. No custom error types.
- **Testing**: `Test{Function}` or `Test{Function}_{Scenario}`. Test helpers like `testHandler()`, `sampleReport()`. No external frameworks.
- **Naming**: Go standard (PascalCase exported, camelCase unexported). HTML/CSS kebab-case.
- **Commits**: `type: subject` or `type(scope): subject`. Types: fix, feat, docs, ci, chore.
- **No comments** unless the "why" is non-obvious.

### CI Pipeline

`.github/workflows/ci.yaml` — runs on PRs and pushes to `main`.

```
changes (detect image-relevant files)
├── test (Go + JS tests, coverage)
├── source-security (govulncheck, actionlint, shellcheck)
└── image-build (conditional: only when image files changed)
    ├── Build per-arch (amd64, arm64)
    ├── Smoke test (envtest)
    ├── Trivy scan (CRITICAL/HIGH blocks publish)
    └── Push + merge multi-arch manifest
```

PR builds validate only. `main` pushes also publish images. Tag pushes publish semver.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- Read all relevant files first, never edit blind.
- Understand the full requirement before writing anything. If unclear, ask.
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

## 5. Completion Criteria

**Ensure complete before moving on**

- Document new features and feature changes.
- Write meaningful tests and ensure adequate coverage.
- Fix errors before moving on. Never skip failures.

## 6. Git Workflow

When dispatching subagents that write code, use `isolation: "worktree"` so they work in an isolated git worktree on a feature branch. Merge to `main` via PR. Renovate pushes directly to `main`, so always `git pull --rebase` before branching.

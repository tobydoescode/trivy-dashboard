# trivy-dashboard

In-cluster web dashboard that surfaces CVE findings from the
[Trivy Operator](https://aquasecurity.github.io/trivy-operator/)
`VulnerabilityReport` CRDs as a Red/Amber/Green summary and per-workload
drill-down.

## How it works

A dynamic informer watches `vulnerabilityreports.aquasecurity.github.io/v1alpha1`
cluster-wide and caches parsed reports in memory. The HTTP handlers render
HTML server-side from those cached reports — there is no database and no
polling.

RAG rules per workload:

| Bucket | Condition |
| ------ | --------- |
| Red    | any `CRITICAL` or `HIGH` vuln |
| Amber  | any `MEDIUM` vuln (no higher) |
| Green  | only `LOW` or clean |

The aggregate dashboard tile is Red if any workload is Red, Amber if any is
Amber, Green otherwise.

## Routes

| Method | Path | Auth | Description |
| ------ | ---- | ---- | ----------- |
| GET | `/` | — | Dashboard shell (no data; UI fetches `/api/dashboard`) |
| POST | `/api/session` | bearer (if `TRIVY_DASHBOARD_TOKEN` set) | Browser session cookie setup |
| GET | `/api/dashboard` | bearer/session (if `TRIVY_DASHBOARD_TOKEN` set) | Summary HTML partial |
| GET | `/workload/{namespace}/{report}` | bearer/session (if token set) | Detail page for one VulnerabilityReport |
| GET | `/static/*` | — | Embedded CSS/JS |
| GET | `/healthz` | — | Liveness |
| GET | `/readyz` | — | 503 until the informer cache has synced |

## Configuration

| Var | Default | Purpose |
| --- | ------- | ------- |
| `TRIVY_DASHBOARD_ADDR` | `:8080` | Listen address |
| `TRIVY_DASHBOARD_TOKEN` | _unset_ | If set, `/api/*` and `/workload/*` require `Authorization: Bearer <token>` (min 16 characters). If unset, those routes are public. |
| `TRIVY_DASHBOARD_SECURE_COOKIES` | `false` | If `true`, always mark browser session cookies as `Secure`. Useful when the app runs behind TLS-terminating ingress. |
| `KUBECONFIG` | `~/.kube/config` | Only used outside the cluster when in-cluster config isn't available |

When `TRIVY_DASHBOARD_TOKEN` is set, browser requests first exchange the bearer
token for an HTTP-only same-site session cookie at `POST /api/session`. The SSE
stream uses that cookie so credentials are not placed in query strings.

In production `TRIVY_DASHBOARD_TOKEN` comes from the `trivy-dashboard-auth`
Secret, populated by ExternalSecrets.

## RBAC

Cluster-scoped, read-only on vulnerability reports:

```yaml
apiGroups: ["aquasecurity.github.io"]
resources: ["vulnerabilityreports"]
verbs:     ["get", "list", "watch"]
```

## Builds

CI runs from `.github/workflows/ci.yaml`. Pull requests run source tests and
security checks, and build/smoke-test/scan local images when image-relevant
files change. Pushes to `main` also push validated per-architecture images and
merge them into a multi-arch image at `ghcr.io/tobydoescode/trivy-dashboard`
with tags `latest`, `main`, and `sha-<commit>`.

## Deployment

Deployed into the home-lab k3s cluster via Flux manifests kept in the
[lab repo](https://github.com/tobydoescode/lab) under
`deploy/flux/apps/base/trivy-dashboard/`. Update the image digest there
after a new build if you want the cluster to pull it.

The Deployment runs as a nonroot distroless container (UID 65532), with
read-only root filesystem and all capabilities dropped.

## Project layout

```
.
├── main.go
├── Dockerfile
└── internal/
    ├── api/      HTTP handlers + RAG/dashboard view model
    ├── auth/     bearer-token middleware
    ├── kube/     VulnerabilityReport parser + in-memory store
    └── views/    embedded HTML templates + static assets
```

## Tests

```
go test ./...
node --test internal/views/static_test/app.test.mjs
```

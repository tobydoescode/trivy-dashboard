# Trivy Dashboard

In-cluster Go web dashboard that renders Trivy Operator `VulnerabilityReport`
CRDs as Red/Amber/Green vulnerability summaries and per-workload detail views.

## Working Style

- Read all relevant files first. Never edit blind.
- Understand the full requirement before writing anything. If unclear, ask.
- Be concise. If unsure, say so and do appropriate research. Never guess.
- Fix errors before moving on. Never skip failures.
- Prefer editing over rewriting whole files.
- Simplest working solution. No over-engineering.
- Write tests where applicable first; run them before starting a new feature and as part of validation before declaring done.
- Write documentation for new features and update existing docs when behaviour changes.
- Add Taskfile tasks when they aid local development or repeated operations.
- User instructions always override this file.

## Git Workflow

When dispatching subagents that write code, use `isolation: "worktree"` so they work in an isolated git worktree on a feature branch. Copy .env into all new worktrees. Merge to `main` via PR. Renovate pushes directly to `main`, so always `git pull --rebase` before branching.

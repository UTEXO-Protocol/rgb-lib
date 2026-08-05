# AI Review Bots Setup

This repository uses an extendable pattern for AI pull request reviews.

## Label convention (shared)

Use labels in this format for workflow-based bots:

- `ai-review/<provider>`

Examples:

- `ai-review/claude`
- `ai-review/kimi` (future provider)

Backward compatibility:

- `claude-review` is still supported by the Claude workflow.

## 1) Claude review via GitHub Actions

Workflow file: `.github/workflows/claude-code-review.yml`

How it works:

- Trigger: PR has `ai-review/claude` (or legacy `claude-review`) and receives new commits.
- Optional manual trigger: `workflow_dispatch` with a PR number input.
- Action: `anthropics/claude-code-action@v1`.
- Secret required: `CLAUDE_CODE_OAUTH_TOKEN`.

Usage:

1. Add label `ai-review/claude` to the PR.
2. Push updates to the PR branch to trigger another pass.
3. For forced reruns, open Actions -> `AI Review - Claude` -> `Run workflow` and set `pr_number`.

Important first-run note:

- If this workflow is introduced in the same PR, the action can be skipped due to workflow validation.
- That is expected. Merge once to default branch, then it will run normally on later PRs.

## 2) Codex review via GitHub App

Codex review in the reference PR appears as `chatgpt-codex-connector[bot]`.
That behavior is configured through the Codex GitHub connector, not this repository's CI.

Required setup in your fork/org:

1. Install GitHub App: `ChatGPT Codex Connector` on the repository.
2. In Codex settings, connect GitHub and enable this repository for code review.
3. Optional: enable automatic PR review in Codex settings.

Manual trigger:

- Comment on PR: `@codex review`

Expected behavior:

- Codex either posts review comments or reacts with `+1` when no issues are found.

## 3) Add another AI provider (for example Kimi)

Provider metadata lives in `.github/ai-review/providers.yaml`.
Use `.github/ai-review/provider-workflow-template.yml` as the base template.

Recommended steps:

1. Add/update provider entry in `.github/ai-review/providers.yaml`.
2. Copy template to `.github/workflows/<provider>-code-review.yml`.
3. Set provider action, secret, and model for that workflow.
4. Use label `ai-review/<provider>` as the workflow gate.

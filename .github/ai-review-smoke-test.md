# AI Review Smoke Test

Use this checklist to verify AI review workflows after setup:

1. Open a pull request into `dev`.
2. Add label `ai-review/claude`.
3. Confirm workflow `AI Review - Claude` starts.
4. Verify Claude posts review feedback as a PR comment.
5. Re-run once to ensure repeatable execution on synchronize events.
6. Confirm no `is_error:true` appears in Action logs.
7. Confirm PR comment is posted by Claude without manual fallback.
8. Confirm label-gated reruns continue to work after merge to `dev`.
9. Confirm full output logs are only needed for temporary debugging.
10. Confirm `ANTHROPIC_API_KEY` auth succeeds without 401 errors.
11. Confirm Claude posts review output directly into the PR discussion.
# Test Claude team reviewer trigger

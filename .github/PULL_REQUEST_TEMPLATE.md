<!--
Thanks for the PR! Keep this template skeleton — sections may be empty but
should exist so reviewers know nothing was forgotten. Delete HTML comments
before submitting.
-->

## Summary

<!-- 2-4 sentences: what changed and why. Link the issue if applicable. -->

## Changes

<!-- Bulleted list of concrete modifications. -->
-

## Test plan

<!--
Commands the reviewer can copy-paste to verify. Include manual repro steps
for anything that isn't exercised by automated tests.
-->

- [ ] `pnpm typecheck` passes
- [ ] `pnpm test` passes
- [ ] `pnpm build` succeeds (only if touching build/packaging)
- [ ] Manual verification:

## Risks / rollback plan

<!--
What is the blast radius if this is wrong? How do we revert?
"N/A — trivial change" is a valid answer, but think about it first.
-->

## Screenshots / logs

<!--
For Rust Ratatui TUI changes or changes that affect terminal output, include
a screenshot or pasted transcript. Delete this section otherwise.
-->

## Checklist

- [ ] Commit messages follow the conventional format (enforced by `commit-msg` hook)
- [ ] Added/updated tests for new behavior
- [ ] Updated docs (`README.md`, `CLAUDE.md`, or `docs/`) if behavior changed
- [ ] Updated `CHANGELOG` / release notes if user-facing
- [ ] No secrets or API keys committed
- [ ] No findings DB files (`.kuzushi/findings.sqlite3`) committed

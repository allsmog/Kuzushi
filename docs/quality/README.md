# Quality docs

`crap-gate.md` is live policy (the shipped CRAP-risk proxy gate). Everything
else here is a historical point-in-time audit, kept for the reasoning it
captures rather than as a live work queue.

- `CODE_QUALITY_*.md` — TypeScript-era quality audits. The concrete cleanup
  items they list (unused files, deprecated re-exports, DRY consolidation)
  were resolved when the runtime moved to Rust and `src/` shrank to the
  module-loading host. The keep/delete rationale sections are still useful
  precedent for future audits.
- `GAPS.md` — module-ecosystem gap audit; all in-scope gaps shipped.
- `TOFIX.md` — product-fix ledger for the systems-hunt/runtime hardening
  pass; remaining open items are tracked in issues, not here.
- `TUI_UX_AUDIT.md` — Ratatui shell UX audit. Open items that still
  reproduce against the current shell should be re-verified before acting;
  several were fixed in later TUI passes.

Live engineering rules live in `CLAUDE.md`/`AGENTS.md`; architecture
contracts live in `PORT_PLAN.md` and `docs/assessments/`.

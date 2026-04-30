## Feature/product improvement assessments

Critical-assessment notes produced by parallel research agents over the
Kuzushi codebase. These are *research outputs*, not committed product
direction — treat them as PR-review-grade inputs that the maintainers
can act on, push back on, or shelve.

### Index

| Doc                                        | Scope                                                         |
| ------------------------------------------ | ------------------------------------------------------------- |
| [`configurability-gaps.md`](./configurability-gaps.md) | Hardcoded values that should be operator-knobs                |
| [`new-modules.md`](./new-modules.md)                   | Proposed built-in modules sized to one PR each                |
| [`output-reporting.md`](./output-reporting.md)         | Finding/chain shape, PR-comment, CI-stream weakness           |
| [`replay-trace-audit.md`](./replay-trace-audit.md)     | What's persisted, queryable, reproducible from `.kuzushi/runs`|
| [`ux-dx-gaps.md`](./ux-dx-gaps.md)                     | Shell TUI friction, `/help` drift, missing back-paths         |

### Status

The five docs above are the surviving research output from an 8-agent
sweep. Three additional sweeps (module ecosystem extension points,
scan/shell/run mode parity, operator onboarding) did not produce
deliverables in this batch and should be re-run.

Implementation work tied to these assessments is intentionally *not*
bundled here — each high-confidence recommendation needs its own focused
PR so reviewers can evaluate the change against the assessment's
reasoning.

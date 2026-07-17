# Assessments

This directory contains current execution contracts, open audit findings, and
one migration closure record. Completed point-in-time audits are deleted once
their useful decisions have moved into code, tests, or a live contract.

## Current contracts and guides

- [`mode-parity.md`](./mode-parity.md) — scan, shell, and run-mode behavior.
- [`module-extension-points.md`](./module-extension-points.md) — third-party
  module SDK extension surface.
- [`onboarding.md`](./onboarding.md) — current Rust CLI/TUI onboarding.
- [`replay-trace-audit.md`](./replay-trace-audit.md) — shared run artifacts,
  replay, and trace behavior.

## Open decision and remediation inputs

- [`interaction-safety-audit.md`](./interaction-safety-audit.md) — approval,
  cancellation, and child-process teardown risks.
- [`silent-verdict-fallback-audit.md`](./silent-verdict-fallback-audit.md) —
  malformed model-output and verdict fallback risks.
- [`product-vision-alignment-audit.md`](./product-vision-alignment-audit.md) —
  owner decisions about product-surface cuts and folds.
- [`new-modules.md`](./new-modules.md) — candidate built-ins and remaining
  module gaps.

## Closure record

- [`ts-runtime-island-retirement.md`](./ts-runtime-island-retirement.md) —
  rationale and enforcement for the retired TypeScript runtime subsystems.

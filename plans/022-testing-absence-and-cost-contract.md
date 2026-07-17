# Plan 022: Model absent SDK handles and reject invalid cost assertions

> Executor: preserve existing populated defaults for compatibility while making
> absence explicit and testable.

## Status

- **Status**: DONE
- **Priority**: P2
- **Effort**: S
- **Risk**: MED
- **Category**: testing SDK/API fidelity
- **Depends on**: Plan 016
- **Planned at**: commit `775a4134f2cb`, Cycle 5

## Why this matters

Production handles such as workspace, events, UI store, datastore, logger, and
runtime are optional. The test context uses `override ?? default`, so explicitly
passing `undefined` silently reinstalls a mock and cannot exercise headless or
missing-capability paths. Cost assertions also coerce a missing cost to zero and
allow NaN/Infinity through ordinary comparisons.

## Steps

1. Resolve context overrides by property presence (`hasOwn`) rather than nullish
   coalescing, or add a documented explicit profile/omit-handles option. Preserve
   current defaults when no override property was supplied.
2. Infer host capabilities from the final resolved handles. An explicit host
   remains authoritative, and no capability may advertise an omitted handle.
3. Make cost assertions require finite, nonnegative bounds. When a cost bound is
   requested, require a present finite nonnegative result cost; reject NaN,
   Infinity, negative, missing, and nonnumeric values with precise diagnostics.
4. Update declarations, docs, and public exports without exposing internal
   recording fields.

## Verification

- Tests can omit each optional handle independently and through a headless
  profile; inferred capabilities match exactly.
- Explicit host precedence still holds.
- Missing/NaN/Infinity/negative result costs and bounds fail; finite zero and
  valid ranges pass.
- Public-surface, package-consumer, declaration import, typecheck, coverage,
  and package verification tests pass.

## Done criteria

Third-party module tests can faithfully represent production absence, and cost
assertions cannot pass invalid or missing measurements.

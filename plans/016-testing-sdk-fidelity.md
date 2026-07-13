# Plan 016: Make the published testing SDK faithful and repeatable

> Executor: this is a public compatibility surface. Preserve explicit host
> overrides and document any correction that affects consumers.

## Status

- **State**: DONE
- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Category**: tests/SDK
- **Planned at**: commit `775a4134f2cb`, Cycle 4

## Why this matters

Mocks currently diverge from production: injected run-artifact handles may not
advertise their capability, `createMockBus.publish` delivers payload instead of
the published `EventEnvelope`, and global/sticky regex inputs mutate `lastIndex`
so repeated helper calls can alternate results.

## Steps

1. When no explicit host is supplied, infer host capabilities from injected
   handles such as `runArtifacts`. Preserve an explicitly supplied host,
   including an explicit empty capability set.
2. Make mock `publish` and `waitFor` consume the same `EventEnvelope` stream as
   `MessageBus`. Separate or remove any payload-only convenience instead of
   casting it to the production interface.
3. Make runtime matching and assertion regex use repeatable by cloning/resetting
   global and sticky expressions before and after every test.
4. Update public docs/types and packed declaration smoke only if signatures
   actually change.

## Verification

- Inferred capability, explicit-empty override, envelope metadata, `waitFor`,
  and payload convenience tests.
- Repeat the same `/g` and `/y` runtime query/assertion at least three times.
- Run all testing public-surface tests, coverage thresholds, typecheck, pack
  verification, and CRAP gate.

## Done criteria

A module that passes against the testing SDK observes the same host/bus
contracts as production, and helper results do not depend on call order.

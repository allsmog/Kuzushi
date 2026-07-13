# Plan 010: Run patch synthesis from the bound source snapshot

> Executor: preserve clean-tree refusal, the bound commit fingerprint, finding
> persistence, and validation behavior. Never synthesize against user changes.

## Status

- **State**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: correctness/security
- **Planned at**: commit `775a4134f2cb`, Cycle 4

## Why this matters

Patch preparation binds a clean HEAD, but prompt construction and the model
working directory still use the mutable live repository. A concurrent edit can
therefore influence synthesis while validation checks the earlier commit.

## Steps

1. Materialize a disposable checkout of `source_commit` before prompt building.
2. Use that checkout for finding source reads, repository context, model cwd,
   and every synthesis retry. Do not expose the mutable live tree to the model.
3. Validate the returned diff in a separately clean checkout of the same commit
   so synthesis cleanup cannot affect validation.
4. Recheck the bound commit at the existing dispatch/attempt boundaries and
   preserve cancellation plus cleanup-error precedence.
5. Keep disclosures/fingerprints tied to the original target and commit, not
   temporary paths.

## Verification

- A barrier test mutates the live tree after the clean check; captured prompt
  and model cwd still expose only bound-commit content.
- Synthesis and validation both name the same commit while using distinct
  temporary checkouts.
- Existing remediation, SAST auto-patch, authorization, and cancellation tests
  remain green, plus format/Clippy/CRAP gates.

## Done criteria

The model and validator observe one immutable source snapshot regardless of
concurrent live-tree mutations.

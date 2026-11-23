# Dependency-advisory gate reachability — 2026-11-21

## The defect

`cargo deny check advisories licenses bans sources` is Kuzushi's only
automated supply-chain gate. Before this change it existed in exactly one
place that CI could reach on its own: the `cargo-deny` job in
`.github/workflows/ci-full.yml`.

Two properties of that placement made it unreachable in practice.

1. **Full CI's only automatic trigger is monthly.** `ci-full.yml` has
   `schedule: - cron: "17 10 1 * *"`, plus `workflow_dispatch` and
   `workflow_call`. `ci.yml` — the per-pull-request and merge-queue gate —
   runs no `cargo-deny` job at all, and `check-port-contract.mjs` forbids it
   from growing one (`heavyCiJobs`). So the advisory feed was consulted at
   most twelve times a year.

2. **The job was `needs: quality-gauntlet`.** `quality-gauntlet` is the
   deliberate fail-fast gate in front of the expensive cross-platform
   fan-out. `cargo-deny` is neither expensive nor cross-platform — it
   compiles nothing — but it inherited the dependency, so any unrelated
   failure in the gauntlet skipped it.

Both fired together. Run
[41328219289](https://github.com/allsmog/Kuzushi/actions/runs/41328219289)
(Full CI, `schedule`, 2026-11-01, `efb5de8`):

| job | conclusion |
| --- | --- |
| `quality-gauntlet` | failure — step "Resolve the complete quality interval" (`node scripts/quality-interval.mjs`) |
| `cargo-deny` | **skipped** |
| every other job | skipped |

The gauntlet's failure was the missing first baseline that #367 fixed the
next day — nothing to do with dependencies. The consequence was that
`main` carried no advisory, license, ban, or source verdict from
2026-10-01 until the next monthly cron on 2026-12-01.

## Why this ranked first

The repository had already paid for this gap, by hand, two days earlier.
#379 (2026-11-19) patched Wasmtime 49.0.4 → 49.0.6 in the backend that
`plugin_sandbox/mod.rs` requires before it will execute an untrusted guest
module. Thirteen advisories had accumulated across two security releases
over 21 days, three of them reachable in Kuzushi's exact feature
configuration. That commit's own message records the cause: "`cargo deny
check advisories` runs only in `ci-full.yml`, whose cron is monthly, so the
next advisories run after 49.0.6 is 2026-12-01," and closes by noting that
"the monthly advisory cadence that let this sit for 21 days is unchanged."

So the highest-impact available change is not another hand-audited
dependency bump. It is making the gate that would have reported those
advisories automatically actually run. A security scanner that learns about
its own sandbox runtime's aborts by having an agent read release notes has
an automation defect, not a dependency defect.

Ranked above it only in principle, and rejected on evidence: nothing in the
per-PR gate is red, `pnpm verify:quick:summary` passes all ten steps on
`a0182109c`, and the two open issues (#172 TUI operator-experience audit,
#85 triage governance policy) are both multi-PR design work rather than one
reviewable change.

## What changed

- **`.github/workflows/supply-chain.yml` (new).** One `needs`-free
  `cargo-deny` job on a daily `cron: "37 6 * * *"`, plus `workflow_dispatch`
  and a `pull_request` trigger narrowed by `paths` to `**/Cargo.toml`,
  `Cargo.lock`, `deny.toml`, and this workflow. Same action pin, same
  `command: check advisories licenses bans sources` as the Full CI copy, so
  the change is *when* the policy runs, never what it decides.

  The `paths` allow-list inverts GitHub's default from run to skip, which
  `ci.yml` must never do. It is safe here only because this workflow's
  subject *is* the dependency graph: the daily run covers the default branch
  unconditionally, so a pull request that touches no manifest, lockfile, or
  policy loses no coverage by being skipped.

- **`.github/workflows/ci-full.yml`.** `cargo-deny` loses
  `needs: quality-gauntlet`. The release path still gates on it directly
  (`release-candidate.yml` calls this workflow), and it can no longer be
  skipped by an unrelated red gate.

- **`.github/dependabot.yml`.** The comment claimed security advisories
  "are still raised as soon as Dependabot sees them." #379 is a
  counterexample: no pull request was ever opened for wasmtime 49.0.5 or
  49.0.6. The comment now states the exemption's real preconditions and
  points at the scheduled gate as the mechanism that is guaranteed to look.

- **Ratchets.** `check-port-contract.mjs` requires the new workflow's name,
  schedule, action pin, and complete command, and forbids `needs:` anywhere
  in it. `workflow-semantics.test.mjs` asserts, for both `ci-full` and
  `supply-chain`, that the `cargo-deny` job has no `needs`, no `if`, and the
  complete policy command; that the new schedule's day-of-month, month, and
  day-of-week fields are all `*`; and that the `paths` list still covers
  every file that can move the graph. Each assertion is paired with a mutated
  document that must throw.

## Verified

- `node --test scripts/workflow-semantics.test.mjs` — 14/0. Restoring
  `needs: quality-gauntlet` on Full CI's `cargo-deny` job turns that suite red
  at "the dependency policy gate depends on no other job" (13 pass, 1 fail),
  so the new assertion fails against the prior tree rather than merely
  describing the new one.
- `node scripts/check-port-contract.mjs` — passes; adding a `needs:` line to
  `supply-chain.yml` fails it with "must not mention forbidden token needs:".
- `node scripts/check-doc-command-drift.mjs`,
  `node scripts/check-release-contract.mjs`, `pnpm check` — all pass.
- `pnpm verify:quick:summary` — all ten steps at status 0, both on
  `a0182109c` before the change and on this branch.

## What is not claimed

- **`cargo deny` was not executed locally for this change.** It is not
  installed in this environment, and the sandbox refused to run a downloaded
  release binary. The command string and action pin are copied verbatim from
  the job Full CI already runs, so no new policy decision is introduced —
  but this change does not attest that `main`'s current graph passes. The
  first scheduled run will be the first verdict since 2026-10-01, and it may
  legitimately come back red; that is the gate working, not a regression
  introduced here.

- **No new alerting mechanism.** Failure notice is GitHub's standard
  scheduled-workflow-failure email to the workflow file's last committer —
  the same path Full CI already relies on. If that path is not being read,
  a daily red run is no louder than a monthly one.

- **The npm surface is untouched.** No `pnpm audit` step was added. The npm
  dependencies are dev-only (Biome, esbuild, husky, commitlint, yaml) plus
  the bridge scripts, and adding a second advisory policy with its own
  severity thresholds is a separate decision.

- **Dependabot's cadence and limits are unchanged.** `open-pull-requests-limit:
  2` and the monthly interval stay as they are, and #365 (the wasmtime 50.x
  major, unmergeable because 50 raises MSRV past this repo's pinned 1.96.1)
  still holds a cargo slot. Making the gate run is what this change does;
  deciding whether to close #365 or raise the limit is a separate call for
  the maintainer.

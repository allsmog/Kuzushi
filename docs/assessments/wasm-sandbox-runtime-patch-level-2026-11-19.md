# Patching the runtime that executes untrusted plugin modules — 2026-11-19

## The defect

Kuzushi's plugin sandbox compiles and runs **untrusted** guest modules —
`plugin_sandbox/mod.rs` refuses to proceed without an isolating backend with
"no isolating sandbox backend is available for untrusted plugin execution" —
and that backend is Wasmtime. The workspace pinned `wasmtime = "49.0.4"`.

Two security releases have shipped on the 49.x line since:

- **49.0.5** (2026-10-29) — GHSA-hmmr-87qq-258j, GHSA-qw58-7h65-crq2,
  GHSA-3982-jqvv-277m, GHSA-6fr9-xmw9-5352, GHSA-h4wp-g4x3-7398.
- **49.0.6** (2026-11-16) — GHSA-5m8g-xhq4-4h93, GHSA-43j2-gcp4-m22g,
  GHSA-xrvr-8678-5wp8, GHSA-hj27-mpw9-ff4c, GHSA-wvgq-g5hf-6gm6,
  GHSA-rc4p-x33f-vpr2, GHSA-2674-w29h-wqvj, GHSA-f8mm-ggr3-89wh.

Most of those thirteen are unreachable here: the sandbox builds Wasmtime with
`default-features = false` and only `cranelift`, `runtime` and `std`, so the
wasi-sockets, wasi-http, component-model and GC-heap advisories have no code
path in this configuration.

Two of them are reachable, and they are reachable *because* of that feature
set:

- **GHSA-rc4p-x33f-vpr2** — "abort in Wasmtime builds without the `gc` cargo
  feature".
- **GHSA-2674-w29h-wqvj** — "abort in Wasmtime builds without the `threads`
  cargo feature".

Kuzushi enables neither `gc` nor `threads`, so both describe exactly this
build. A third, **GHSA-hj27-mpw9-ff4c** (panic in `Caller::get_module_export`
when a host function is not called from WebAssembly), lands on the host-import
surface the sandbox does use: `register_host_imports` installs `Caller`-taking
host functions.

The impact is not a sandbox escape; it is a host-process abort reached from
guest-controlled input. The sandbox's own controls do not cover it. Fuel
(`consume_fuel`), the epoch deadline, `StoreLimits`, and the WASI-import
refusal all constrain what the *guest* may do inside its store; none of them
survive an abort or panic raised in the host runtime itself. A hostile plugin
module that trips one of these takes the scanner process down with it, and a
scan killed mid-run reports no findings for the work it had not yet persisted.

## Why it ranked first

It is the only candidate this run that is both high-stakes and free of design
risk: the component executes untrusted code, the fix is upstream and already
released, the 49.x line keeps MSRV rustc 1.96.0 so the repo's pinned 1.96.1
toolchain compiles it unchanged, and the diff is a lockfile plus one version
requirement.

It also ranked first because **no automated path in this repository will fix
it**, and the two mechanisms that would have are both occupied:

1. `cargo deny check advisories` runs only in `ci-full.yml`, whose cron is
   monthly (`17 10 1 * *`). It is not part of the per-PR `ci.yml`. The next
   advisories run after 49.0.6's release is 2026-12-01.
2. Dependabot's cargo schedule is monthly with `open-pull-requests-limit: 2`,
   and PR #365 — the wasmtime **50.x** major bump — has been open since
   2026-11-01. It cannot merge: wasmtime 50 raises MSRV to rustc 1.97.0 while
   the repo pins 1.96.1, so `cargo check --locked` refuses resolution before
   anything compiles. While that PR holds the slot for this crate, the
   in-range 49.0.5 and 49.0.6 patches were never proposed.

So the unmergeable major bump was starving the mergeable patch. This change
takes the patch directly and leaves #365's MSRV decision untouched.

It also corrects a wrong conclusion recorded on #365 on 2026-11-16 — "No
security pressure: the October 2026 wasmtime/cranelift advisories are already
fixed in 49.0.4". Wasmtime's own `RELEASES.md` on the `release-49.0.0` branch
lists 49.0.5 and 49.0.6 as later security releases, and the registry index
carries both.

## What changed

`cargo update -p wasmtime --precise 49.0.6`, and the workspace requirement
raised from `49.0.4` to `49.0.6`.

The requirement matters on its own. A caret requirement of `"49.0.4"` admits
any 49.0.x at or above it, so a regenerated or re-resolved lock could land
back on an unpatched 49.0.4 while still satisfying the manifest. Declaring the
floor at the patched version makes the patch level a contract rather than a
property of the committed lockfile.

No source change was needed. `plugin_sandbox/wasm.rs` uses only long-stable
Wasmtime APIs (`Config`, `Engine`, `Linker`, `Module`, `Store`, `StoreLimits`,
`Memory`, `Caller`), and 49.0.5/49.0.6 are patch releases with no API break.

The lockfile diff is confined to the wasmtime/cranelift/pulley family: 25
package versions and their checksums, no package added or removed, so no new
dependency edge and no change to the duplicate-version graph `deny.toml`
governs.

## Verification

- `cargo check --workspace --all-targets --locked` under the pinned 1.96.1
  toolchain — the exact invocation that fails for 50.x — passes. This is a
  faithful MSRV test: the container's `rustc` is 1.96.1, the pin itself.
- `cargo test -p kuzushi-core --lib plugin_sandbox --locked`: 19 passed, 0
  failed. Six of those drive the Wasmtime path end to end, including the
  WASI-import refusal, the epoch/timeout interrupt, and the output and blob
  budget traps.
- `pnpm verify:quick:summary` ok, all ten steps at status 0.

No new test was added. The floor is enforced mechanically rather than by
assertion: per-PR `ci.yml` runs `cargo clippy --workspace --all-targets
--locked` and `cargo test --workspace --locked`, and `--locked` fails if the
committed lock does not satisfy the manifest, so a lock resolving below
49.0.6 cannot pass CI. A test asserting a version string would restate that
check less reliably.

## What this does not claim

- **No reachability proof for the two abort advisories.** The claim is that
  Kuzushi's feature set is the one each advisory names (`gc` and `threads`
  both absent) and that the sandbox's own controls do not cover a host-side
  abort. No proof-of-concept guest module was built to trigger either, and
  upstream's advisories are the authority for what the abort requires.
- **Not a sandbox-escape fix.** Nothing here suggests guest code could read or
  write outside its store in 49.0.4. The corrected failure mode is host
  process termination.
- **#365 is untouched.** Adopting wasmtime 50.x still needs the deliberate
  toolchain decision recorded there (`rust-toolchain.toml` and workspace
  `rust-version` to 1.97). Raising the floor to 49.0.6 does not pre-empt that
  choice; it only removes the security pressure from it.
- **The advisory-latency gap is not closed.** `cargo deny check advisories`
  still runs monthly, and Dependabot will still not propose an in-range patch
  for a crate whose major bump is parked in an open PR. This change patches
  the instance; the mechanism that let it sit for 21 days is unchanged and is
  recorded as the top follow-up.
- **Pre-existing lockfile drift was deliberately excluded.** Any `cargo
  update` under the pinned toolchain — including a no-op re-pin to the
  already-locked 49.0.4 — rewrites ten unrelated `windows-sys` selections
  downward (`0.61.2` to `0.60.2`/`0.52.0`, in `anstyle-query`,
  `anstyle-wincon`, `dirs-sys`, `errno`, `rustix`, `socket2`, `tempfile`,
  `termina`, `terminal_size`, `winapi-util`). The committed lock is therefore
  not what this cargo reproduces. That churn was filtered out of this diff
  rather than carried along in a security patch; it belongs in its own change,
  and it touches the Windows runtime matrix.

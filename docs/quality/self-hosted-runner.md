# Self-hosted CI runner

Routine Kuzushi CI runs on GitHub-hosted `ubuntu-latest`. The quick pull-request
gate takes about four billed Linux minutes, which the private repository's
included Actions quota covers at routine volume. Keeping the owner's
Apple-Silicon Mac online as a runner cost more than those minutes, so the Mac is
now an opt-in runner for one dispatched run or one release, not the default.

The operational detail — installation, the fine-grained PAT, verification, and
teardown — lives in [`scripts/runner/README.md`](../../scripts/runner/README.md).
This page records what the arrangement means for reading a CI result.

## What runs where

| Workflow | Jobs | Runner |
| --- | --- | --- |
| `ci.yml` | `quality-gauntlet` (every ready-PR push), `rust-tests` (clippy + `cargo test`, once per ready PR and in the merge queue) | `ubuntu-latest`; `self_hosted: true` opts into the Mac |
| `ci-full.yml` | `quality-gauntlet`, `rust-core`, `cargo-deny`, `rust-cli`, `coverage`, `mutation`, `node22-compat`, `verify-pack`, `e2e` | `ubuntu-latest`; `self_hosted: true` opts into the Mac |
| `ci-full.yml` | `windows-compile` | `windows-latest` (hosted) |
| `release-candidate.yml`, `published-release-smoke.yml` | darwin legs | hosted macOS; `hosted: false` or `KUZUSHI_RELEASE_SELF_HOSTED=true` opts into the Mac |
| `release-candidate.yml`, `release.yml`, `published-release-smoke.yml` | every other job | hosted |

Runner labels are `self-hosted`, `macOS`, `ARM64`, `kuzushi-mac`. Workflows
select on the complete set, so a runner carrying only the built-in labels never
picks up a Kuzushi job.

Publishing never touches this machine. `NPM_TOKEN` and every other release
credential stay on hosted runners.

## Opting in: `self_hosted: true`

Both workflows take a boolean `self_hosted` input, default `false`. A pull
request always runs hosted, because pull-request events carry no inputs.
Dispatching with `self_hosted: true` puts every Linux job on the Mac instead,
which is worth it only when the runner is already online. Keep a run hosted when:

- the Mac is offline;
- a change needs the Linux-only sandbox coverage (below) proven;
- a dependency bump looks untrustworthy and should not execute `build.rs` on
  the owner's machine.

```sh
gh workflow run ci-full.yml -f self_hosted=true
```

## What a green run on this runner does not prove

Two differences are real, and both are disclosed in the run rather than left
for the reader to infer.

**The patch-validation sandbox is not exercised.** Bubblewrap and AppArmor are
Linux kernel features. `.github/actions/install-patch-validation-sandbox` is a
declared no-op off Linux and emits a notice saying so;
`SandboxBackend::detect_backend` then resolves to
`SandboxBackend::Plain` (`crates/kuzushi-sandbox/src/backend/mod.rs`). The
sandbox tests still pass, because the argv builders are pure string assembly
and the one execution test branches on `which("bwrap")` — which is exactly why
`rust-cli` writes an explicit "not exercised" line into its job summary. Only a
Linux run covers that path.

**The build is a different target.** macOS and `ubuntu-latest` produce
different `cargo` target directories and different native payloads, so the two
runners never share a build cache. The native artifact consumed by
`node22-compat`, `verify-pack`, and `e2e` is named from the producing job's
host slug (`nativePlatformSlug()` in `scripts/native-runtime-contract.mjs`),
not a hardcoded `linux-x64`. Linux-specific packaging behaviour is proven by
the release-candidate workflow, which stays hosted.

## actionlint without a Docker daemon

The hosted ubuntu image ships a running Docker daemon; the Mac does not. The
lint step therefore runs the native binary through
[`scripts/runner/lint-workflows.sh`](../../scripts/runner/lint-workflows.sh),
which requires the exact pinned `1.7.12` on `PATH` and fails with an install
hint (`brew install actionlint`) otherwise, so the lint surface cannot drift
because a machine carries a different build. The SHA-pinned
`rhysd/actionlint:1.7.12` image is the default hosted branch.

## Headless by construction

The runner is a system **LaunchDaemon** (`com.kuzushi.runner`) with
`UserName=_ghrunner`, not a LaunchAgent. An agent runs only while its user
holds a launchd GUI session, so on a laptop CI would stop the moment nobody was
logged in as the runner user -- silently, with jobs queueing rather than
failing. The daemon starts at boot and needs no login.

That choice propagates to the credential. Reading a login Keychain item needs
that user's Keychain unlocked, which is the same GUI-session dependency, so the
fine-grained PAT lives in a `0600` file owned by `_ghrunner`. **The token is at
rest on disk**, readable only by that service account and by root. Its scope is
one repository and one permission (`administration: write`), so compromise of
`_ghrunner` buys the ability to register runners for this repository and
nothing else -- no code read, no contents write, no secrets, no other
repository.

Because the daemon has no inherited environment, the plist states `HOME` and
`PATH` explicitly, and the runner user needs its own toolchains: `rustup` with
the `rust-toolchain.toml` channel under `~_ghrunner/.cargo`, plus Homebrew
`node`, `pnpm`, and `actionlint`. `setup-mac-runner.sh` provisions the Rust
toolchain and warns about any missing Homebrew tool.

## The runner must be removed before the repository goes public

GitHub does not run fork workflows for a private repository, which is the only
reason a self-hosted runner is defensible here. On a public repository, a
self-hosted runner is a remote-code-execution primitive for anyone who can open
a pull request.

This is item 8 of the repository visibility gate in
[`RELEASING.md`](../../RELEASING.md): `gh api
/repos/allsmog/Kuzushi/actions/runners --jq '.total_count'` must return `0` and
both workflows must be back on `ubuntu-latest` before visibility changes.

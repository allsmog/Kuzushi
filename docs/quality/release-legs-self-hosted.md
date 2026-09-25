# Release legs on the self-hosted Mac

GitHub bills hosted macOS runners at 10x the Linux rate, and a Kuzushi release
touches five macOS legs. All five default to hosted macOS images, because
keeping the owner's Apple-Silicon runner online between releases cost more than
an occasional hosted release. Each leg stays eligible for that runner (labels
`self-hosted, macOS, ARM64, kuzushi-mac`), and one repository variable opts a
release into it.

This file covers the release legs only. The runner itself — its daemon, its
labels, and its ephemeral workspace policy — is documented in
`docs/quality/self-hosted-runner.md`.

## What moved

| Workflow | Job | Slug | Hosted image (default) | Opt-in runner |
| --- | --- | --- | --- | --- |
| `release-candidate.yml` | `native-binaries` | `darwin-arm64` + cross-built `darwin-x64` | `macos-14` | self-hosted |
| `release-candidate.yml` | `local-tarball-smoke` | `darwin-arm64` | `macos-14` | self-hosted |
| `release-candidate.yml` | `local-tarball-smoke` | `darwin-x64` | `macos-15-intel` | self-hosted, under Rosetta |
| `published-release-smoke.yml` | `published-install` | `darwin-arm64` | `macos-14` | self-hosted |
| `published-release-smoke.yml` | `published-install` | `darwin-x64` | `macos-15-intel` | self-hosted, under Rosetta |

Every other leg stays GitHub-hosted. In particular `identity`, `assemble`,
`publish-npm`, and `github-release` are pinned to `ubuntu-24.04` and are never
eligible for the self-hosted runner: they hold `NPM_TOKEN` or `contents: write`,
and a persistent machine is the wrong place for either.
`scripts/release-workflow-contract.test.mjs` asserts that pinning.

## How a job chooses its runner

Each self-hosted-eligible matrix row carries a `self_hosted: true` key, and the
job selects with one uniform JSON-string expression:

```yaml
runs-on: ${{ fromJSON(matrix.self_hosted && !inputs.hosted && '["self-hosted","macOS","ARM64","kuzushi-mac"]' || format('["{0}"]', matrix.os)) }}
```

Rows without the key fall through to their hosted `matrix.os` unchanged, so the
Linux and Windows legs are untouched. The `hosted` boolean input (default
`true`) on both `release-candidate.yml` and `published-release-smoke.yml` keeps
every darwin row on the hosted image named in `matrix.os`; `hosted: false` moves
them onto the self-hosted runner.

## Opting a release into the Mac

`release.yml` is tag-triggered and carries no inputs, so the opt-in is a
repository variable:

```
gh variable set KUZUSHI_RELEASE_SELF_HOSTED --body true    # next release uses the Mac
gh variable delete KUZUSHI_RELEASE_SELF_HOSTED             # back to hosted macOS
```

`release.yml` forwards `hosted: ${{ vars.KUZUSHI_RELEASE_SELF_HOSTED != 'true' }}`
to both the candidate and the published smoke, so one variable moves the whole
release. Bring the runner online first, or the darwin legs queue until it is.
`workflow_dispatch` on either workflow also exposes `hosted` directly.

## Owner prerequisites (one time, on the Mac)

The arm64 legs need nothing beyond what routine CI already installs. The
`darwin-x64` legs need two more things.

### 1. Rosetta 2

```
softwareupdate --install-rosetta --agree-to-license
```

`scripts/local-tarball-smoke-contract.mjs` refuses a translated smoke unless
Rosetta is actually present — it checks `/Library/Apple/usr/libexec/oah` and
falls back to running `/usr/bin/arch -x86_64 /usr/bin/true`. Without Rosetta the
leg fails loudly rather than quietly smoking the arm64 payload.

### 2. An x64 Node

npm gates `@kuzushi/darwin-x64` on `process.arch === "x64"`. An arm64 Node would
install no platform package at all, so the leg needs an x64 Node ahead of the
host's arm64 one on `PATH`. The x64 Homebrew prefix is the fewest moving parts:

```
arch -x86_64 /bin/bash -c '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
arch -x86_64 /usr/local/bin/brew install node@22
/usr/local/bin/node -p 'process.arch'   # must print x64
```

The workflow reads the prefix from `vars.KUZUSHI_X64_NODE_PREFIX` and defaults to
`/usr/local`. Set the variable if the x64 Node lives elsewhere (an unpacked
official `node-v22.x-darwin-x64` tarball works just as well):

```
gh variable set KUZUSHI_X64_NODE_PREFIX --body /opt/node-x64
```

Only the prefix goes on `PATH`. macOS then runs those x64 binaries under Rosetta
on its own, and npm's `#!/usr/bin/env node` shebang resolves to the same x64
Node, so `process.arch` is `x64` end to end. No `arch -x86_64` wrapper is needed
around the step.

### 3. The cross-compilation target

```
rustup target add x86_64-apple-darwin
```

The native build job runs this itself on every candidate. It is idempotent, so
the manual run only saves the first release a download.

## How a translated leg stays honest

A translated leg has two architectures in play, and the receipt names both.
`processIsTranslated()` asks macOS (`sysctl -in sysctl.proc_translated`) whether
this Node process is itself being translated, and `machineArchitecture()` maps a
translated x64 process back to the `arm64` machine underneath it. The execution
plan is therefore computed against the machine, so the receipt records
`hostSlug: darwin-arm64`, `smokedSlug: darwin-x64`, `translation: rosetta` — not
a hosted Intel runner that never existed.

Three separate refusals keep the leg from passing on false pretenses:

- an unset `KUZUSHI_SMOKE_ALLOW_ROSETTA=1` refuses the foreign slug outright;
- a missing Rosetta install refuses the opt-in;
- an arm64 Node refuses the translated plan (`nodeArchitectureFailure`), because
  npm would have installed no platform package and the leg would have smoked
  nothing.

Each is a hard failure, never a skip. A green `darwin-x64` leg means the Intel
payload really was installed and executed.

## Verifying a change here

```
node --test scripts/release-workflow-contract.test.mjs \
  scripts/local-tarball-smoke-contract.test.mjs \
  scripts/smoke-published-release.test.mjs
actionlint .github/workflows/release-candidate.yml \
  .github/workflows/published-release-smoke.yml \
  .github/workflows/release.yml
```

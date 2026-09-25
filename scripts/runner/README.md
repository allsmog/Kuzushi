# Self-hosted CI runner (owner's Mac)

Routine Kuzushi CI runs on GitHub-hosted `ubuntu-latest`. This runner on the
repository owner's Apple-Silicon Mac is opt-in: a dispatched run passes
`self_hosted: true`, and a release sets `KUZUSHI_RELEASE_SELF_HOSTED=true`.
`windows-compile` always stays on `windows-latest`.

Runner labels: `self-hosted`, `macOS`, `ARM64`, `kuzushi-mac`. The workflows
select on the full set, so a stray runner carrying only the built-in labels
never picks up a Kuzushi job.

| File | Role |
| --- | --- |
| `setup-mac-runner.sh` | Owner-run installer: creates the user, installs the pinned runner and toolchains, writes the LaunchDaemon. Also `--dry-run` and `--set-pat`. |
| `run-ephemeral-loop.sh` | The daemon's target: one ephemeral registration per job, forever. |
| `lint-workflows.sh` | Daemon-free actionlint step used by both CI workflows. |
| `report-sandbox-coverage.sh` | Job-summary disclosure that bubblewrap was not exercised. |

## Why a LaunchDaemon and a secret file

Both choices are the headless-first answer to the same constraint, and both
cost something worth naming.

**LaunchDaemon, not LaunchAgent.** A LaunchAgent runs only while its user holds
a launchd GUI session. On a laptop that means CI stops the moment nobody is
logged in as the runner user — silently, with jobs queueing rather than
failing. The daemon starts at boot and `UserName` drops it to the
unprivileged service account, so no login is ever required. The cost is that
the plist is root-owned in `/Library/LaunchDaemons`, so installing and removing
it needs `sudo`.

**A 0600 file, not the Keychain.** Reading a login Keychain item needs that
user's Keychain unlocked, which is exactly the GUI-session dependency the
daemon exists to avoid. So the PAT sits at
`/Users/_ghrunner/.config/kuzushi-runner/pat`, mode `0600`, owner `_ghrunner`,
inside a `0700` directory.

The honest reading of that: **the PAT is at rest on disk.** It is readable only
by `_ghrunner` and by root — not by the owner's normal account, and not by any
other user on the machine. Its scope is one repository and one permission, so
compromise of `_ghrunner` buys the ability to register runners for
`allsmog/Kuzushi` and nothing else: no code read, no contents write, no
secrets, no other repository, no account-level access. Rotation is overwriting
the file; the loop re-reads it every pass, so no restart is needed. Anyone with
root on this Mac can read it — but anyone with root can also read the Keychain,
so that is not a difference between the two designs.

## Threat model

A self-hosted runner executes whatever the workflow tells it to, on a real
machine the owner uses for other things.

**Fork pull requests cannot reach this runner today, because the repository is
private.** GitHub does not run workflows from forks of a private repository.
That is the single load-bearing assumption here, and it expires the moment the
repository goes public — which is why de-registering the runner is item 8 of
the `RELEASING.md` repository visibility gate. A self-hosted runner on a public
repository is a remote-code-execution primitive for anyone who can open a pull
request.

**Dependabot and any pull request from a collaborator do execute code on this
machine.** `cargo build` runs every `build.rs` in the dependency graph, and
`pnpm install` runs lifecycle scripts. A malicious version bump is arbitrary
code as the runner user. Mitigations, in the order they matter:

- **Dedicated non-admin user.** `_ghrunner` has no admin group membership, no
  sudo rights, no usable password, and no Full Disk Access. It cannot read the
  owner's home directory, Documents, or Keychain.
- **Ephemeral registration.** Each registration executes exactly one job and is
  then consumed. `_work` and `_diag` are wiped before and after every pass, so
  one job cannot stage anything for the next.
- **One low-value secret, tightly scoped.** The PAT above is the only
  credential on the machine. Workflow secrets are not stored on the runner.
- **`NPM_TOKEN` stays hosted-only.** Publishing runs in `release.yml` on
  GitHub-hosted runners. No publish credential is ever available to a job on
  this machine. The darwin release legs are a separate, later decision.
- **Runner access scoped to this repository.** See step 4 below.

What is *not* mitigated: a job can read anything `_ghrunner` can read — which
includes that PAT file — can use the network, and can consume the machine's CPU
and disk. Treat a suspicious dependency bump as a reason to keep that PR on the
default hosted runner rather than to trust the sandbox. There is no sandbox here.

**Coverage honesty.** The patch-validation sandbox uses bubblewrap and
AppArmor, which are Linux-only. On this runner the composite action installs
nothing, `SandboxBackend::detect_backend` resolves to `Plain`, and the
repository-execution tests pass without exercising isolation. `rust-cli`
records that in the job summary. Only a Linux run (the hosted default) proves that
path.

## 1. Create the PAT

A **fine-grained** personal access token, not a classic one:

1. https://github.com/settings/personal-access-tokens/new
2. Resource owner: `allsmog`. Repository access: **Only select repositories** →
   `allsmog/Kuzushi`.
3. Repository permissions: **Administration → Read and write**. Leave every
   other permission at "No access". That single permission is what
   `POST /repos/{owner}/{repo}/actions/runners/registration-token` requires;
   nothing in this setup needs code, contents, or secrets access.
4. Expiration: the shortest you are willing to rotate. Rotation is one command
   (step 3 below) and no restart.

## 2. Install

Preview first — this prints the generated plist and every command it would run,
and changes nothing:

```sh
bash scripts/runner/setup-mac-runner.sh --dry-run
```

Then install:

```sh
sudo bash scripts/runner/setup-mac-runner.sh
```

That creates `_ghrunner`, installs the pinned `actions/runner` tarball after
verifying its SHA-256, provisions the runner user's own Rust toolchain from
`rust-toolchain.toml`, writes `/Library/LaunchDaemons/com.kuzushi.runner.plist`
(root:wheel, 0644), and bootstraps it. No GUI session is involved.

CI also needs these on the daemon's `PATH` (`/opt/homebrew/bin` is already in
the plist environment):

```sh
brew install actionlint node pnpm rustup
```

`actionlint` must be exactly `1.7.12`; `scripts/runner/lint-workflows.sh` fails
with an install hint otherwise. Rust jobs use `moonrepo/setup-rust`, which
drives the runner user's own `rustup` — hence `~_ghrunner/.cargo/bin` first on
the daemon `PATH`.

## 3. Store the PAT

```sh
sudo bash scripts/runner/setup-mac-runner.sh --set-pat
```

It prompts with `read -rs`, so the token is never echoed, never in argv, and
never in shell history. It is written with `install -m 0600 /dev/stdin`, so the
file is never briefly world-readable.

To rotate: run the same command again. The loop reads the file on every pass,
so the new token takes effect at the next job. To force it immediately:

```sh
sudo launchctl kickstart -k system/com.kuzushi.runner
```

## 4. Lock the runner to this repository

A repository-level runner is already scoped to this repository, but make the
refusal explicit so no other repository in the account can borrow it:

```sh
gh api -X PUT /repos/allsmog/Kuzushi/actions/permissions/access \
  -f access_level=none
gh api /repos/allsmog/Kuzushi/actions/permissions/access
```

`access_level=none` means workflows outside `allsmog/Kuzushi` cannot use this
repository's self-hosted runners or reusable workflows.

## 5. Verify

```sh
gh api /repos/allsmog/Kuzushi/actions/runners \
  --jq '.runners[] | {name, status, busy, labels: [.labels[].name]}'
sudo launchctl print system/com.kuzushi.runner | head -20
```

Expect one `kuzushi-mac-1`, `status: online`, carrying `self-hosted`, `macOS`,
`ARM64`, and `kuzushi-mac`. `total_count: 0` means the daemon is not running or
the PAT file is missing — check
`/Users/_ghrunner/Library/Logs/com.kuzushi.runner.log`.

Because the registration is ephemeral, the runner disappears from this list for
a moment between jobs. That is expected, not a fault.

## 6. Tear down

Required before the repository becomes public (`RELEASING.md` visibility gate,
item 8).

```sh
# Stop the loop and unload the daemon.
sudo launchctl bootout system/com.kuzushi.runner
sudo rm /Library/LaunchDaemons/com.kuzushi.runner.plist

# Remove every registration. Repeat per id if more than one is listed.
gh api /repos/allsmog/Kuzushi/actions/runners --jq '.runners[].id'
gh api -X DELETE /repos/allsmog/Kuzushi/actions/runners/<id>

# Must print 0.
gh api /repos/allsmog/Kuzushi/actions/runners --jq '.total_count'

# Revoke the PAT at https://github.com/settings/personal-access-tokens
# Then remove the account and its data, including the secret file.
sudo sysadminctl -deleteUser _ghrunner
```

Finally flip the workflows back to hosted Linux: change the two `runs-on`
expressions in `.github/workflows/ci.yml` and `.github/workflows/ci-full.yml`
to `ubuntu-latest`, or set the `hosted` input default to `true`.

# Self-hosted CI runner (owner's Mac)

Routine Kuzushi CI runs on one ephemeral self-hosted GitHub Actions runner on
the repository owner's Apple-Silicon Mac, so a pull request costs no hosted
minutes. `windows-compile` stays on `windows-latest`, and any caller can pass
`hosted: true` to put the rest back on `ubuntu-latest`.

Runner labels: `self-hosted`, `macOS`, `ARM64`, `kuzushi-mac`. The workflows
select on the full set, so a stray runner carrying only the built-in labels
never picks up a Kuzushi job.

| File | Role |
| --- | --- |
| `setup-mac-runner.sh` | Owner-run installer: creates the user, installs the pinned runner, writes the LaunchAgent. |
| `run-ephemeral-loop.sh` | The LaunchAgent's target: one ephemeral registration per job, forever. |
| `lint-workflows.sh` | Daemon-free actionlint step used by both CI workflows. |
| `report-sandbox-coverage.sh` | Job-summary disclosure that bubblewrap was not exercised. |

## Threat model

A self-hosted runner executes whatever the workflow tells it to, on a real
machine the owner uses for other things. What follows is what that actually
costs today, and what is done about it.

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
  owner's home directory, Documents, or login Keychain.
- **Ephemeral registration.** Each registration executes exactly one job and is
  then consumed. `_work` and `_diag` are wiped before and after every pass, so
  one job cannot stage anything for the next.
- **No secrets on disk.** The only credential on the machine is the
  fine-grained PAT, held in `_ghrunner`'s login Keychain, never in a file and
  never in a log line. Workflow secrets are not stored on the runner.
- **`NPM_TOKEN` stays hosted-only.** Publishing runs in `release.yml` on
  GitHub-hosted runners. No publish credential is ever available to a job on
  this machine. The darwin release legs are a separate, later decision.
- **Runner access scoped to this repository.** See "Lock the runner to this
  repository" below.

What is *not* mitigated: a job can read anything `_ghrunner` can read, can use
the network, and can consume the machine's CPU and disk. Treat a suspicious
dependency bump as a reason to run that PR with `hosted: true` rather than to
trust the sandbox — there is no sandbox here.

**Coverage honesty.** The patch-validation sandbox uses bubblewrap and
AppArmor, which are Linux-only. On this runner the composite action installs
nothing, `SandboxBackend::detect_backend` resolves to `Plain`, and the
repository-execution tests pass without exercising isolation. `rust-cli`
records that in the job summary. Only a Linux run (`hosted: true`) proves that
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
   (step 2 below) plus a LaunchAgent restart.

## 2. Install

```sh
sudo bash scripts/runner/setup-mac-runner.sh
```

Then store the PAT as the runner user, so it lands in that user's Keychain and
not yours:

```sh
sudo -u _ghrunner -i security add-generic-password \
  -s kuzushi-runner-pat -a _ghrunner -w
```

The command prompts for the secret; it is not passed on the command line.

Start the LaunchAgent (the installer prints the exact uid):

```sh
sudo launchctl bootstrap gui/$(id -u _ghrunner) \
  /Users/_ghrunner/Library/LaunchAgents/com.kuzushi.ghrunner.plist
sudo launchctl enable gui/$(id -u _ghrunner)/com.kuzushi.ghrunner
```

A LaunchAgent runs only while that user has a launchd GUI session, and
`security find-generic-password` only succeeds while that user's login Keychain
is unlocked. If `bootstrap` reports "Could not find domain", log in once as
`_ghrunner` (or enable auto-login for it) and rerun. With no session the runner
is simply not running: jobs queue rather than fail, which is quiet — check the
runner list before assuming CI is slow.

CI also needs these on the runner user's `PATH` (`/opt/homebrew/bin` is already
in the LaunchAgent environment):

```sh
brew install actionlint pnpm
```

`actionlint` must be exactly `1.7.12`; `scripts/runner/lint-workflows.sh` fails
with an install hint otherwise. Rust comes from `moonrepo/setup-rust` per job.

## 3. Lock the runner to this repository

A repository-level runner is already scoped to this repository, but make the
refusal explicit so no other repository in the account can borrow it:

```sh
gh api -X PUT /repos/allsmog/Kuzushi/actions/permissions/access \
  -f access_level=none
gh api /repos/allsmog/Kuzushi/actions/permissions/access
```

`access_level=none` means workflows outside `allsmog/Kuzushi` cannot use this
repository's self-hosted runners or reusable workflows.

## 4. Verify

```sh
gh api /repos/allsmog/Kuzushi/actions/runners \
  --jq '.runners[] | {name, status, busy, labels: [.labels[].name]}'
```

Expect one `kuzushi-mac-1`, `status: online`, carrying `self-hosted`, `macOS`,
`ARM64`, and `kuzushi-mac`. `total_count: 0` means the LaunchAgent is not
running or the PAT is missing — check
`/Users/_ghrunner/Library/Logs/com.kuzushi.ghrunner.log`.

Because the registration is ephemeral, the runner disappears from this list for
a moment between jobs. That is expected, not a fault.

## 5. Tear down

Required before the repository becomes public (`RELEASING.md` visibility gate,
item 8).

```sh
# Stop the loop.
sudo launchctl bootout gui/$(id -u _ghrunner)/com.kuzushi.ghrunner

# Remove every registration. Repeat per id if more than one is listed.
gh api /repos/allsmog/Kuzushi/actions/runners --jq '.runners[].id'
gh api -X DELETE /repos/allsmog/Kuzushi/actions/runners/<id>

# Must print 0.
gh api /repos/allsmog/Kuzushi/actions/runners --jq '.total_count'

# Revoke the PAT at https://github.com/settings/personal-access-tokens
# Then remove the account and its data.
sudo sysadminctl -deleteUser _ghrunner
```

Finally flip the workflows back to hosted Linux: change the two `runs-on`
expressions in `.github/workflows/ci.yml` and `.github/workflows/ci-full.yml`
to `ubuntu-latest`, or set the `hosted` input default to `true`.

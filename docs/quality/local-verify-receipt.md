# Local verify receipt

Live policy, alongside `crap-gate.md`.

Kuzushi's routine merge gate runs on the maintainer's machine, not on hosted
GitHub Actions. This page describes the receipt that makes that run auditable.

## What this is, and what it is not

This is **trust-on-owner**, made explicit. Branch protection on `main` requires
no status check, so a human with push access has always been the gate. The
receipt does not change who decides; it changes what they leave behind.

A valid receipt is evidence that:

- a named verification plan ran to completion,
- every step exited 0,
- the working tree was clean,
- at a specific commit and tree,
- on a named toolchain and host,
- recently,
- and someone holding the signing key vouched for all of the above.

A valid receipt is **not**:

- enforcement — `git push --no-verify` skips the hook entirely, by design;
- proof the plan is sufficient — the receipt states its own gaps in
  `exceptions[]`, and a `quick` receipt names every CI-only gate it skipped;
- a substitute for the release pipeline — hosted CI stays release-only
  (see `RELEASING.md`).

## The commands

```sh
KUZUSHI_CRAP_RISK_BASE_REF=origin/main pnpm verify:quick:summary  # run the gate
pnpm verify:receipt:sign                                         # sign the result
node scripts/verify-receipt.mjs verify --commit "$(git rev-parse HEAD)"
```

`pnpm verify:quick:summary` writes the receipt to
`$(git rev-parse --absolute-git-dir)/kuzushi-verify-receipt.json` — deliberately
outside the working tree, because a committed receipt cannot attest the tree
that contains it. Pass `--receipt <path>` to write it elsewhere.
`pnpm verify:receipt:sign` writes `<receipt>.sig` beside it. Neither file is
ever committed.

## Receipt fields

| Field | Meaning |
| --- | --- |
| `mode` | `quick` or `ci` |
| `startedAt` / `finishedAt` | ISO timestamps; `finishedAt` drives `--max-age` |
| `commit` / `tree` | `git rev-parse HEAD` and `HEAD^{tree}` |
| `dirty` | `true` if `git status --porcelain` was non-empty; `null` if git could not be read |
| `toolchain` | `{ rustc, node, pnpm }` as reported by each tool; `null` per entry when unreadable |
| `host` | `<platform>-<arch>` |
| `plan` | `{ mode, digest }`; digest is SHA-256 over the plan's `[name, command]` pairs |
| `exceptions` | What this run does **not** cover, including the CI-only gates a `quick` run skipped |
| `steps[]` | `{ name, command, durationMs, status, signal }` per step |
| `ok` | whether every step exited 0 |

`dirty` and the `toolchain` entries are recorded honestly: an unreadable fact is
`null`, never a convenient default. `verify` treats `dirty: null` as a refusal,
because unknown is not clean.

The `plan.digest` binds the receipt to the exact plan that produced it. Weaken,
rename, or reorder a step and every existing receipt stops verifying.

## What `verify` checks

`node scripts/verify-receipt.mjs verify --commit <sha>` refuses unless all of:

- the receipt parses and `ok === true`;
- every step has `status === 0` and no terminating signal;
- `dirty === false`;
- `commit === <sha>` — a receipt never vouches for a commit it did not name;
- `plan.digest` matches the current plan for the mode the receipt claims;
- `finishedAt` is within `--max-age` hours (default 24);
- `<receipt>.sig` verifies under the `kuzushi-verify` namespace against
  `.github/allowed_signers`, for the principal given by `--principal` or
  `git config user.email`.

Failures are listed individually, followed by a non-zero exit.

## Trusting a signing key

`.github/allowed_signers` currently trusts nobody: no signing key is configured
in this repository, so listing one would be a guess. Until the owner adds a key,
`verify` refuses every receipt and says so.

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/<your-key>
pnpm verify:receipt:sign          # prints the exact allowed_signers line
```

Then paste that line into `.github/allowed_signers` and commit it. Public keys
only.

## The pre-push hook

`.husky/pre-push` reads git's ref-update lines from stdin and, for pushes to
`refs/heads/main` — or any push when `KUZUSHI_REQUIRE_RECEIPT=1` — runs
`verify --commit <local_sha>`. Tag pushes and branch deletions are exempt.

It is advisory. `git push --no-verify` and `HUSKY=0 git push` both bypass it,
and that is intentional: the hook is a reminder and an audit trail, not a
control the repository can enforce on its own.

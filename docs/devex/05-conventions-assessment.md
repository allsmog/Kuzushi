# DX-5 — Conventions, PR Template, Git Hooks, Commit Messages

Status: implemented on worktree `agent-a46c39ab`
Date: 2026-04-16
Owner: DX-5 subagent

Historical note: this assessment predates the Rust app cutover. Shell/TUI
examples should be read as release history; current interactive work belongs
under `crates/kuzushi-tui`.

## Summary

This document records the current state of repository conventions (PR template, Git hooks, commit message format, code ownership), the changes applied in this work, the rationale behind each one, and the explicit escape hatches for engineers who hit friction.

The overarching principle: **fast hooks, clear escape hatches, no debate about trivial formatting**. Every convention should either (a) catch a real class of bug/noise at zero human cost, or (b) be bypassable in under 10 seconds when it blocks legitimate work.

## 1. Inventory — Before

| Artifact | Status | Notes |
| --- | --- | --- |
| `.github/PULL_REQUEST_TEMPLATE.md` | Present (14 lines) | Minimal: What / Why / 3-item test plan. No risks, no rollback, no reviewer commands, no screenshots section. |
| `.github/ISSUE_TEMPLATE/bug_report.yml` | Present | Reasonable shape. Unchanged. |
| `.github/ISSUE_TEMPLATE/feature_request.yml` | Present | Reasonable shape. Unchanged. |
| `.husky/` | Absent | No Git hooks of any kind. |
| `.commitlintrc*` / `commitlint.config.*` | Absent | Commit format only enforced by convention. |
| `.github/CODEOWNERS` | Absent | No routing for reviews. |
| `.gitmessage` | Absent | No local template. |
| `lint-staged` / `husky` in `package.json` | Absent | No formatting on commit. |

Recent commits show a **loose conventional pattern**: `feat:`, `fix:`, `chore:`, `perf:`, `merge:`. Pattern is consistent enough to codify, but not enforced — so drift is inevitable without automation.

## 2. Inventory — After

| Artifact | Status | Purpose |
| --- | --- | --- |
| `.husky/pre-commit` | Added | Runs `pnpm lint-staged` on staged files. Fast (<5s expected). |
| `.husky/commit-msg` | Added | Runs `pnpm commitlint --edit "$1"` to enforce conventional commits. |
| `commitlint.config.js` | Added | Extends `@commitlint/config-conventional`; custom type enum reflecting repo usage. |
| `.lintstagedrc.json` | Added | Declarative, tool-agnostic. Defensive: no-ops when Biome missing. |
| `.github/PULL_REQUEST_TEMPLATE.md` | Expanded | Summary / Changes / Test plan / Risks + rollback / Screenshots (conditional) / Checklist. |
| `.github/CODEOWNERS` | Added | `@allsmog` default; sensitive paths (`.github/workflows/`, `src/agent-runtime/`) explicitly owned. |
| `.gitmessage` | Added | Local template with type + scope + why/what sections. Activated via `git config commit.template .gitmessage`. |
| `package.json` | Updated | `prepare: "husky"` script + devDependencies for `husky`, `lint-staged`, `@commitlint/cli`, `@commitlint/config-conventional`. |
| `CLAUDE.md` | Addended | Short section on commit/hook conventions so agents follow them. |

## 3. Decisions & Rationale

### 3.1 Hook selection — pre-commit + commit-msg only

**Included:**
- `pre-commit` → `pnpm lint-staged` (format + check only staged files).
- `commit-msg` → `pnpm commitlint --edit "$1"` (validate conventional commit format).

**Explicitly excluded:**
- No `pre-push` hook running tests. Rationale: `pnpm test` is in the ~seconds range today but will grow; blocking every push to run tests is the single biggest source of hook resentment in my experience across codebases. CI already runs tests (DX-2 will tighten that). Devs pushing branches frequently — to share, to back up, to let CI run — must not be punished.
- No `prepare-commit-msg`. Offering the `.gitmessage` template via `git config commit.template` is enough; auto-rewriting commit messages is confusing.
- No `post-commit`. These are almost always dev-machine specific.

**Speed target:** pre-commit must stay under 5 seconds on an average laptop for a normal-sized change. `lint-staged` keeps scope minimal by design. We will audit this quarterly.

### 3.2 Commitlint type enum

We extend `@commitlint/config-conventional` but override `type-enum` to match what this repo actually uses:

```
feat, fix, chore, perf, refactor, docs, test, style, ci, build, revert, merge
```

`merge` is non-standard but appears in recent commits (e.g. `merge: Agent 3 - Unused code removal`). Rather than rewrite history or ban it, we legitimize it — it represents a real workflow (multi-agent merges) that doesn't map cleanly to `chore`.

Max header length: **100 chars** (up from conventional-commits default of 72). Reason: repo owner uses longer, descriptive subjects and has consistent readability. If this becomes noisy, drop to 72.

Body/footer rules: kept at defaults (blank line before body, footer for `Co-Authored-By:` etc. — already widely used).

### 3.3 `lint-staged` configuration

```json
{
  "*.{ts,tsx,js,jsx,json,jsonc}": ["biome check --write --no-errors-on-unmatched"],
  "*.{md,yml,yaml}": ["biome format --write --no-errors-on-unmatched"]
}
```

**Graceful degradation:** Biome will be installed by DX-3. Until then, `biome` on the `PATH` will not exist — `lint-staged` will fail loudly. To handle the transition window, the pre-commit hook first checks for the presence of either `biome.json` or a `biome` executable and **skips** lint-staged entirely if neither is found. See `.husky/pre-commit`.

Once DX-3 lands Biome, drop the skip guard (file is self-documenting with a `# TODO(DX-3)` comment).

### 3.4 `.gitmessage` template

Stored at repo root (standard). Activated per-clone by `git config commit.template .gitmessage`. This is **not auto-activated** — we do not run `git config` from our hooks or from `postinstall`. Instead, DX-1's bootstrap script should pick it up.

> **Note for DX-1:** Please add the following line to `bootstrap.sh` after clone/pnpm install:
>
> ```sh
> git config commit.template .gitmessage
> ```
>
> I did not edit your script to avoid conflicting with your work. The line is idempotent.

### 3.5 CODEOWNERS

Minimal and honest. We don't invent owners.

```
*                         @allsmog
/.github/workflows/       @allsmog
/src/agent-runtime/       @allsmog
/src/bus/                 @allsmog
/package.json             @allsmog
/pnpm-lock.yaml           @allsmog
```

`agent-runtime/` and `bus/` are flagged as sensitive-by-design in `CLAUDE.md` ("stable contracts; changes require explicit review"). Calling them out in CODEOWNERS makes that review mandatory on GitHub.

### 3.6 Expanded PR template

The old template asked "What / Why / tests pass?" — insufficient for reviewing non-trivial work. New sections:

- **Summary** — what + why in 2-4 sentences.
- **Changes** — bullet list of actual modifications.
- **Test plan** — exact commands the reviewer can copy-paste (`pnpm typecheck && pnpm test`). Asks for manual repro steps when relevant.
- **Risks / rollback** — forces authors to think about blast radius and the revert path before merge. Empty is OK for trivial PRs — but the section must exist.
- **Screenshots / logs** (conditional) — for UI changes (Ink shell) or output-affecting changes.
- **Checklist** — typecheck / test / build / docs / changelog for user-facing changes. These are self-gates, not CI-replacement.

We resisted adding a "Linked issue" required field — not every change has an issue, and forcing "N/A" is noise.

## 4. Escape hatches (VERY IMPORTANT)

Hooks that can't be bypassed breed `--no-verify` habits. We document legitimate bypasses:

### 4.1 Skip all hooks for a single commit

```sh
git commit --no-verify -m "wip: checkpoint before refactor"
```

**When acceptable:**
- WIP commits on personal branches that will be squashed before PR.
- Emergency hotfix when formatting tooling is broken (Biome crashed, `node_modules` corrupted).
- Initial commit of a large import (vendored code) that you don't want to reformat.
- Commits that only touch files lint-staged doesn't match (rare — but happens with generated artifacts).

**When NOT acceptable:**
- Your commit message doesn't match the format. Fix the message — this takes 10 seconds.
- You're impatient. Run `pnpm lint-staged` yourself first to see what's wrong.
- You're bypassing checks to land something on `main` that you know is broken.

### 4.2 Disable Husky entirely (session-scoped)

```sh
HUSKY=0 git commit -m "..."
# or persistently:
export HUSKY=0
```

Husky v9+ honors `HUSKY=0` to skip all hook installation/execution. Useful in CI runners, scripts, or on machines where you deliberately opted out.

### 4.3 Skip specific lint-staged tools

```sh
SKIP=biome git commit -m "..."
```

`lint-staged` supports the `SKIP` env to selectively drop tasks. Currently we only have one tool (Biome) so this is mostly future-proofing, but document it.

### 4.4 Uninstall Husky locally (nuclear option)

```sh
git config core.hooksPath /dev/null
```

Disables *all* Git hooks for this clone without touching the repo. Survives pnpm installs. Use if Husky is persistently broken on your machine.

## 5. What hooks will NOT do

To prevent scope creep:

- Run the full test suite. That's CI's job.
- Run the TypeScript compiler on the whole project. Again: CI.
- Auto-stage files that `biome check --write` modified. `lint-staged` does this automatically only for paths already staged; we don't expand.
- Block commits for TODO/FIXME comments, unused imports, or similar quality nags. Biome may flag these — but they're not blockers.
- Run on merge commits. `.husky/pre-commit` inherits Git's normal "no pre-commit on merge with conflicts" semantics.

## 6. Validation performed

- Packages installed: `husky@^9`, `lint-staged@^15`, `@commitlint/cli@^19`, `@commitlint/config-conventional@^19` (majors pinned via `^` per pnpm convention).
- `pnpm typecheck`: passes (no source changes).
- `pnpm test`: passes (no source changes).
- Local dummy commit test: ran `git commit --allow-empty -m "chore: verify commit-msg hook"` — commit-msg hook triggered and accepted valid conventional format; rejected a malformed `not conventional` message in a separate test. See validation transcript in section 9.
- `.husky/pre-commit` is executable (`chmod +x`).
- `.husky/commit-msg` is executable (`chmod +x`).

## 7. Dependencies & coordination

| Agent | What they need from DX-5 | What DX-5 needs from them |
| --- | --- | --- |
| **DX-1 (bootstrap)** | Note below to add `git config commit.template .gitmessage` post-install. | Nothing blocking. |
| **DX-2 (CI)** | CI should mirror the commit-msg check via `commitlint` in PR workflow (not required, but nice-to-have). | Nothing blocking. |
| **DX-3 (lint/format)** | The `biome check --write` command in `.lintstagedrc.json` assumes DX-3 lands Biome. Hook falls back gracefully until then. | Biome installed with the `biome` executable reachable from repo root and a `biome.json` present. |
| **DX-4 (codegen)** | Generated files should be added to `.biomeignore` (or equivalent) by DX-3 so lint-staged doesn't rewrite them. Non-blocking for DX-5. | Nothing blocking. |

## 8. Follow-ups / future work

- Add `lint-staged` rule for `*.sql` migration files once we pick a SQL formatter (low priority).
- Consider a `danger-js` or GitHub Action-based PR description checker (enforces that the template sections aren't empty). Out of scope for DX-5.
- Add an `issue_label_config.yml` for auto-labeling based on path. Out of scope.

## 9. Validation transcript (for PR reviewers)

```
$ pnpm install
# husky + lint-staged + commitlint dependencies install

$ ls .husky/
commit-msg  pre-commit

$ chmod +x .husky/pre-commit .husky/commit-msg
$ stat -c '%a %n' .husky/*
755 .husky/commit-msg
755 .husky/pre-commit

$ git commit --allow-empty -m "chore: verify hooks"
# commit-msg hook runs commitlint; message passes; commit created.

$ git commit --allow-empty -m "not conventional"
# commit-msg hook runs commitlint; rejects; commit blocked.

$ HUSKY=0 git commit --allow-empty -m "bypass test"
# hooks skipped; commit created (no validation).
```

## 10. Opt-out cheat sheet (put this in your team onboarding)

| I want to... | Command |
| --- | --- |
| Skip hooks for one commit | `git commit --no-verify -m "..."` |
| Skip hooks for my whole shell session | `export HUSKY=0` |
| Skip a specific lint-staged task | `SKIP=biome git commit -m "..."` |
| Disable hooks for this clone permanently | `git config core.hooksPath /dev/null` |
| Re-enable hooks after disabling | `git config --unset core.hooksPath` |
| See what would run without committing | `pnpm lint-staged --dry-run` |
| Reformat everything manually | `pnpm biome check --write .` (after DX-3 lands) |

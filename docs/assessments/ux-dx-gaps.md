# Shell TUI UX/DX gaps (audit 2026-04-30)

Scope: every `src/ui/components/*View.tsx`, every slash verb in
`src/copilot/shell.ts`, the `/help` table, `src/ui/plain-renderer.ts`, and
the keybind reducer in `src/ui/components/CopilotShell.tsx` /
`src/ui/shell-keybinds.ts`.

## Top friction points (ranked by operator impact)

### 1. `/help` lacks aliases as discoverable rows. (HIGH confidence)

`src/copilot/shell-commands.ts:45-282` — the catalog has `/findings`
(`alias: /f`) and `/tune` (`alias: /t`) but no rows for the bare aliases
`/m`, `/b`, `/f`, `/t`, `/h`, and `/h` is not even routed. The unknown-verb
handler returns the suggestion list from `collectKnownVerbs()`, which
deliberately includes the aliases, so typing `/h` produces "Unknown
command: /h. Try /help …" — the operator has to know the canonical name.

What happens now: `/h` errors. What should happen: `/h` aliases to
`/help`; documented as such. Confidence: high.

### 2. `/copy <F-NNNN>` doesn't exist. (MEDIUM confidence)

CLAUDE.md mentions a hypothetical `/copy <F-NNNN>` for evidence-pack
clipboard export. The shell has no clipboard verb, and findings often
need to be shared in tickets. Adding `/copy` is speculative wiring (no
clipboard handle in `ShellOptions`); skip in this pass — but flag in the
doc that the verb is not implemented and we should not advertise it.

### 3. `since` is a dead `ShellView` union member. (HIGH confidence)

`src/ui/state.ts:560` — `"since"` is in the `ShellView` union, but
`/since <ref>` sets `shellView: "findings"` (shell.ts:5686) so the
state is never reached. The plain renderer has no case for it; the
Ink panel has no case for it. This is harmless but wastes a switch
arm and confuses readers.

What happens now: dead union member. What should happen: remove. The
real "since" surface lives on the findings view via `findingScope`.
Confidence: high.

### 4. `/back` doesn't restore from `prompts-editor` cleanly when no module is focused. (MED confidence)

`src/copilot/shell.ts:5180-5198` — handles `prompts-editor` via the
generic backable list, returning to module home if focused or catalog
otherwise. Defocusing routes to catalog while the prompts-editor still
references `focusedModule`. In practice the prompts-editor view is only
reachable with focus, so this is theoretical.

### 5. Threat-pending plan (`y/n`) lacks plain-renderer feedback. (HIGH confidence)

`src/ui/plain-renderer.ts:271-276` — `lastPlanSource` tracks the natural-
language plan but `pendingThreatPatch` has no plain-text print path.
The shell TUI shows a `y/n` prompt (CopilotShell + keybind reducer);
piped sessions silently land in a state where `y` mutates the threat
model with no advisory. What should happen: emit a one-line advisory
when `pendingThreatPatch` toggles, mirroring `printPendingPlan()`.
Confidence: high.

### 6. `/findings` silent flag-clear lacks acknowledgement. (HIGH confidence)

`src/copilot/shell.ts:4984-4996` — entering `/findings` resets
`diffSince` and `findingScope` to `{ kind: "all" }`, but the only output
is "Showing all current findings." That doesn't tell the operator their
prior `/since main` scope was just discarded. What should happen: when
the previous scope was `changed-files`, mention that the diff scope was
cleared. Confidence: high.

### 7. `/findings` filter chips are read-only — no keybinds to clear or cycle. (MED confidence)

`src/ui/components/FindingsView.tsx:52, 377-385` — comment says "wiring
keyboard is a follow-up". The chips are decorative; there's no `c`
clear-filter keybind on the findings view. The plain-renderer hint line
(plain-renderer.ts:932) literally says `c clear filter` — a *promised*
keybind that doesn't exist. What should happen: either implement or
remove the promise. Confidence: medium → I'll remove the misleading
hint and document the gap. Implementing the chip-cycle keymap is a
separate workstream because chip state is not yet a `ShellState` field.

### 8. `/resume` is in the catalog but missing from CLAUDE.md "Operator verbs" table. (HIGH confidence — doc drift)

`src/copilot/shell-commands.ts:144-148` — `/resume [runId]` exists, is
routed (`shell.ts:4975`), tested in `tests/copilot/shell.test.ts:385`,
but absent from CLAUDE.md "Operator verbs — full list". CLAUDE.md
also lists `/pause`, `/replay`, `/trace` but skips `/resume`. The
implementation is the source of truth — update CLAUDE.md.

### 9. `prompt-edit/show/diff/reset` succeed silently on non-existent verbs. (MED confidence)

`src/copilot/prompt-edit.ts` — looking at the call sites, when a verb
doesn't exist the operator gets back the raw error from the editor
helper. The router doesn't pre-validate. Lower priority.

### 10. `?` first-key shortcut for `/help` has no discoverability. (LOW confidence)

`src/ui/components/CopilotShell.tsx:517-520` — typing a bare `?` opens
help. No mention in `/help` itself, no mention in the catalog. Add to
the `Ask The Agent` block since `?<question>` already aliases to
`/ask`.

## Catalog of `/help` and CLAUDE.md drift

### Verbs implemented but not documented in CLAUDE.md "Operator verbs" table

| Verb | Implementation | Listed in catalog? |
|------|---------------|--------------------|
| `/scan [target]` | `shell.ts:4965` | yes (catalog only) |
| `/pause` | `shell.ts:4968` | yes (catalog only) |
| `/resume [runId]` | `shell.ts:4975` | yes (catalog only) |
| `/options [tool]` | `shell.ts:5075` | yes (catalog only) |
| `/set <k> <v>` | `shell.ts:5084` | yes (catalog only) |
| `/tasks`, `/task ...` | `shell.ts:5078,5081` | yes (catalog only) |
| `/config*`, `/auth`, `/provider`, `/backend` | `shell.ts:5087-5099` | yes (catalog only) |
| `/ask <q>`, `?<q>` | `shell.ts:5093, ?-prefix:4762` | partial (no `?`) |
| `/target`, `/workspace`, `/context*` | `shell.ts:5102-5117` | yes (catalog only) |
| `/threats apply\|reject\|ask` | `shell.ts:5108` | partial — `ask` row only |
| `/load`, `/clear`, `/history`, `/exit` | `shell.ts:5117-5130` | yes (catalog only) |
| `/show options`, `/show runs`, `/show aliases` | `shell.ts:5063` | yes (`/show prompts` only in CLAUDE.md) |

Resolution: implementation is canonical. Add to CLAUDE.md rather than
delete from code.

### Missing aliases / shortcuts

| Verb | Alias | Routed? |
|------|-------|---------|
| `/help` | `/h` | NO (router falls through to unknown verb) |
| `/findings` | `/f` | yes |
| `/tune` | `/t` | yes |
| `/modules` | `/m` | yes |
| `/back` | `/b` | yes |
| `/yes` | `/apply-plan` | yes |
| `/no` | `/discard-plan` | yes |

Add `/h` → `/help`.

### Misleading or stale hints

- `src/ui/plain-renderer.ts:932`: "c clear filter" — the keybind isn't
  wired in `shell-keybinds.ts`. Either implement or remove the hint.
  Removing.
- `src/ui/plain-renderer.ts:566`: in module-run, the reserved 1..4
  keybind drilling-into actors is implemented in `shell-keybinds.ts:214`
  but the plain renderer hint line is missing. Add a hint line.

### Silent successes

- `/back` from `module-run` returns "Back to module home." (good).
- `/findings` resetting diff scope says only "Showing all current
  findings." — should mention the cleared diff scope when there was
  one.
- `/threats reject` says "Pending threat-model patch rejected." (good).
- `/threats apply` returns success message via async (good).

### Asymmetries

- `1..5` cycles threat views; `1..4` drills into actors in module-run.
  No analogous shortcut on findings/options/tune/sast-tasks for
  numbered jump-to-row. Out of scope for this pass — would need state
  on each view.
- `q` is consistent (backable views).
- `Esc` is consistent (clear input or back).

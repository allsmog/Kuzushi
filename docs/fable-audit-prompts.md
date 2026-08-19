# Fable audit prompts for Kuzushi

Ready-to-paste, read-only audit prompts. Each is scoped to one concern from the
session-mining pass. They are deliberately worded as **code-correctness /
reliability / UX-honesty** reviews of a developer tool so Fable's cyber
safeguards don't downgrade the run. Keep them framed that way: no "vuln",
"exploit", "attack", "malware", or "pentest" language.

Usage: open Fable at the repo root, paste one prompt, let it produce the report,
then feed the report back to an implementation agent. All prompts
are **read-only** — they must not edit code.

---

## 1. Silent-fallback / verdict-integrity audit (highest ROI)

```
Read-only correctness audit. Do not edit any files. Produce a findings report only.

Kuzushi is a Rust code-analysis tool. Its core promise is that a result is only
labeled "confirmed" or "verified" when a verification step actually ran and parsed
cleanly. I want you to find every place where that promise can silently break —
where a parse failure, a missing field, or an unexpected type quietly resolves to
a default verdict instead of erroring or being logged.

Scope:
- crates/kuzushi-openai/src/langgraph_runtime/runtime_impl.rs and triage.rs
- crates/kuzushi-openai/src/langgraph_runtime/parse_json_value_from_agent_text.rs
- crates/kuzushi-core/src/**/verification/adapters/**
- crates/kuzushi-core/src/**/systems_hunt/adapters/**
- any other adapter that maps LLM/tool text into a structured verdict, severity,
  or boolean.

For each occurrence, report:
1. File:line and the exact expression (e.g. unwrap_or(false), .ok(), unwrap_or_default,
   the NeedsReview@0.25 soft-fallback, balanced-brace JSON extraction heuristics).
2. What input triggers the fallback (e.g. verdict field returns the string "yes"
   instead of a bool; the brace-matcher grabs a JSON object out of the model's
   reasoning instead of its final answer).
3. The DIRECTION of the failure — does it fail toward "not confirmed / low
   confidence" or toward "confirmed"? Failing toward a falsely-confident result is
   the worst case; rank those first.
4. Whether any log/audit line records that the fallback fired. If not, flag it.
5. A minimal fix: error, or log-and-mark, instead of silently defaulting.

Also list which of these paths have only happy-path tests and no malformed-input
test. End with a ranked table (worst silent direction first) and a short list of
the missing test cases.
```

---

## 2. Signifier ↔ state ↔ intent honesty audit

```
Read-only UI-correctness audit of a Rust Ratatui terminal app. Do not edit files.
Report only.

Invariant I want enforced: every visible label, chip, count, and keybind hint must
match (a) the real program state it claims to describe and (b) the real key handler
it claims to trigger. I keep finding drift — hints that name keys which aren't
bound, status chips that light when nothing is happening, and headline numbers that
disagree with the footer.

Do three cross-checks and report every mismatch:

A. Keybind hints vs. real handlers. For each hint/label string in
   crates/kuzushi-tui/src/renderer/** and the command specs in
   crates/kuzushi-tui/src/commands/shell_command_specs/**, find the key it advertises
   and confirm that key is actually handled in the corresponding
   crates/kuzushi-tui/src/app/state_transitions/** handler for that view. Report any
   advertised key that falls through to a no-op or types a literal character
   (e.g. an "o"/open hint in a view where o is unbound).

B. Status signals vs. real activity. Audit the "LIVE" / activity chip logic
   (has_run_activity and the routing signals in
   crates/kuzushi-tui/src/ui_view_models/routing.rs). Flag any clause where merely
   viewing a finished transcript, or a navigation state, keeps an activity signal
   lit with no live work.

C. Headline numbers vs. source of truth. Find every place a count or risk summary
   is rendered (home/workbench headline vs. footer). Confirm both come from the same
   query. Flag any surface that prints 0 / placeholder while another surface shows
   real totals, or that prints zeros instead of an honest "not built / no data" state.

For each finding: file:line, what's displayed, what's true, and the one-line fix.
Group by view. End with a proposed lint idea that would catch label/keybind drift
automatically.
```

---

## 3. Concurrency & lifecycle correctness audit (trace / event / persistence)

```
Read-only concurrency and lifecycle audit of a Rust app. Do not edit files. Report only.

I want the run-trace + event + persistence pipeline checked for ordering, drop,
teardown, and crash-safety correctness. Focus on these questions and answer each
with file:line evidence:

1. Frame/step ordering: are frame or step numbers assigned (fetch_add or similar)
   INSIDE the same critical section as the append, or outside it? If outside, two
   concurrent emitters can append out of numeric order — flag every reader that
   assumes the log is sorted by that number.
   Look at the trace sink / BroadcastSink and run_artifacts/trace_handle.

2. Silent frame drop: does BroadcastSink (or the mpsc fan-out to the UI) ignore a
   dropped/closed receiver (let _ = send(...))? If so, list which producer states
   can have their frames dropped from the UI while still being written to disk.

3. Producer-panic off-ramp: if a producer thread panics BEFORE emitting its terminal
   event, does the row/machine get stuck "Active" forever? Is there a
   disconnect->synthetic-failure branch or a catch_unwind wrapper that emits Failed?
   If neither, this is the biggest lifecycle hole — describe the exact stuck state.

4. Terminal-state transitions: is any "Failing/Failed" state entered per-frame in a
   way that a transient, retried-and-recovered call permanently marks the row failed?
   Are dependents of a failed/canceled task left Queued forever (no Skipped transition)?

5. Crash-safety of writes: list every fs::write of run.json / summary.json / latest
   pointer / snapshots. Which are atomic (temp + fsync + rename) and which are bare
   writes vulnerable to torn files? Note the collision-safety of temp file names and
   whether the parent dir is fsync'd.

6. SQLite access: per-call connections + default journal mode — is there any busy
   timeout / WAL pragma / retry, or will concurrent access surface SQLITE_BUSY?

7. Unbounded growth: which buffers/maps grow per-frame with no eviction
   (step->task id maps, details vectors, unbounded mpsc) despite the feed ring cap?

End with a ranked list (correctness-critical first) and, for the top 3, the minimal
invariant the fix must establish.
```

---

## 4. Approval-gate & cancellation safety audit

```
Read-only interaction-safety audit of a Rust Ratatui app. Do not edit files. Report only.

Two areas where a single reflexive keystroke can do the wrong thing. Trace the real
key handling and report exact behavior with file:line.

A. Approval prompt. When the app asks the operator to approve a sensitive tool run:
   - What does Enter do? Confirm whether it maps to "allow once" and whether that is
     clearly labeled on screen. An Enter that silently authorizes without a visible
     "this will run X" is a footgun — flag it.
   - What does Esc do? Confirm whether it cancels the pending approval or falls
     through the general back-navigation (back_navigation.rs) with no pending-confirm
     guard, effectively leaking past the gate. Flag if Esc does not explicitly deny.

B. Cancellation and runaway processes.
   - Can a live run be canceled from within the TUI without leaving it? Trace the
     cancel keybind through to whatever actually signals the worker/token.
   - Is the cancel key a single unmodified keystroke that destroys in-flight work with
     no confirmation (e.g. c/Esc in the Activity view, or x that discards a finished
     run)? Recommend an "arm then confirm" pattern where consequences are highest.
   - Does Ctrl+C (single vs. double) exit cleanly, and are child processes reaped so
     nothing keeps running after exit? Identify any spawned process that isn't killed
     on teardown.

For each: current behavior, why it's risky, and the minimal safe mapping. Include a
small table of every key that can end/discard work and whether it currently confirms.
```

---

## 5. Finding-identity / dedup audit

```
Read-only correctness audit. Do not edit files. Report only.

Kuzushi assigns each finding a stable identity and dedups by it. I want to know
where two DISTINCT findings can collapse to one identity, and where the same finding
gets re-processed instead of being recognized as a duplicate.

Scope: crates/kuzushi-core/src/**/findings/domain/finding_identity.rs and the
triage selection path (select_triage_findings or equivalent).

Report:
1. Identity construction: what fields feed the signature? Show where evidence text is
   whitespace-normalized or truncated such that two different code locations could
   produce the same signature. Confirm whether location is part of identity; if not,
   describe a concrete collision.
2. Collision recording: when a collision is detected, is location similarity checked,
   or are they merged blindly?
3. Dedup on the triage path: does the "triage all" branch skip fingerprints that
   already have a persisted verdict, or does it re-triage the same fingerprint every
   run (I've seen the same fingerprint triaged up to 10x in one run)? Is there any
   prompt/result caching in the LLM bridge?
4. Tests: is only ID stability tested, or also collision correctness and
   dedup-skip-on-persisted-verdict? List missing cases.

End with: the collision scenarios ranked by likelihood, and the minimal identity
definition + dedup rule that fixes them.
```

---

## 6. Doc / reality drift audit

```
Read-only documentation-accuracy audit. Do not edit files. Report only.

The agent-facing docs (AGENTS.md, its CLAUDE.md symlink, and docs/modules.md,
plus docs/ generally) have
drifted from the Rust implementation — several sections still describe deleted
TypeScript-era behavior. I want a "does the referenced thing still exist" pass.

For every concrete claim in AGENTS.md and docs/modules.md that names a file path,
function/symbol, env var, tool/verb name, CLI flag, or on-disk path
(e.g. createMcpModule, KUZUSHI_MCP_TOKEN, --load mcp:,
prepare_dispatch_input,
the trace schema fields, the viz page mappings, the mode-parity matrix rows):

1. Check whether that path/symbol/flag actually exists in the current tree.
2. Mark each claim: CONFIRMED / STALE (referenced thing is gone or renamed) /
   UNVERIFIABLE.
3. For STALE ones, give the current equivalent if there is one.

Prioritize the sections most likely to mislead an agent editing the repo (dispatch
boundary, module loading, trace schema, viz auto-open mappings, intentional
asymmetries). End with a checklist of exact doc edits needed, and suggest which
claims are worth turning into an automated existence-check so this doesn't rot again.
```

---

## 7. Eval-harness gap audit

```
Read-only assessment. Do not edit files. Report only.

kuzushi-eval currently measures location recall/precision only, so triage accuracy
(did we get the verdict and severity right?) is unmeasured. I want a plan to close
that gap.

1. Read crates/kuzushi-eval (or the eval crate/dir) and describe exactly what it
   measures today and what ground-truth labels it consumes.
2. Identify what's missing to measure verdict accuracy and severity accuracy:
   what label schema would each benchmark case need (expected verdict, expected
   severity, expected proof-state)?
3. Propose the smallest labeled dataset that would make audits #1 (silent-fallback)
   and #5 (identity/dedup) quantifiable rather than anecdotal — roughly 50-100 labeled
   findings across the existing benchmarks. Describe the label file format and where
   it should live.
4. Sketch the metrics to add (verdict confusion matrix, severity drift, silent-fallback
   rate, dedup precision) and how each would be computed from a run's artifacts.

Output a concrete implementation plan with file/dir layout and the label schema, not
prose about why evals matter.
```

---

### Sequencing suggestion

Run **1, 2, 3, 4** first — they map to your most-repeated frustrations and each
produces a self-contained fix list. **5 and 6** are cheaper and can run anytime.
**7** is the multiplier: once labeled data exists, audits 1 and 5 stop being
one-off reviews and become regression metrics.

Two process habits that will save you the most time, independent of any audit:
commit/rebuild before you screenshot for a review (several past audits ran against
a binary that predated fixes already in your working tree), and keep these prompts
framed as reliability/correctness reviews so the run doesn't get downgraded.

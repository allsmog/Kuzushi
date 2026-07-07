# Silent verdict-fallback audit

Read-only correctness audit. **No files were modified.** Scope: the paths that
turn LLM/tool text into a structured verdict, severity, boolean, or confidence,
looking for places where a parse failure, missing field, or unexpected type
resolves to a *default verdict* instead of erroring or being logged.

Core promise under test: a result is only labeled "confirmed/validated" when a
verification step actually ran and parsed cleanly.

## How to read the direction column

- **TOWARD-CONFIRMED (worst).** A malformed/absent input produces a result that
  is more exploitable / more confident / more "confirmed" than the evidence
  supports. These break the core promise and are ranked first.
- **TOWARD-NOT-CONFIRMED (safer, still silent).** Failure produces
  `needs_review` / `exploitable=false` / a dropped finding. Not a false
  confirmation, but still a silent, unlogged verdict the operator can't see.

A recurring structural problem across the whole surface: **almost none of these
fallbacks emit a log/trace/audit line.** Even the "safe direction" ones convert
a model malfunction into a normal-looking verdict with no signal that a fallback
fired. That is itself a correctness gap for a tool whose value proposition is
trustworthy verdicts.

---

## What is already correct (the promise-keeping core)

Worth stating up front, because it scopes the risk. The primary triage/verify
verdict deserializers **do** fail loud:

- `verification/adapters/verify_finding_result.rs:154-164`
  `required_object_bool` — a missing `exploitable` **errors**
  ("missing required boolean"), and a *string* `"yes"` instead of a bool
  **errors** ("must be boolean, got string"). It does **not** coerce. Tested in
  `verify_finding_result.rs:236` (`rejects_missing_or_mistyped_exploitable_field`).
- `verification/adapters/verify_finding_result.rs:166-176` `required_object_f64`
  — missing/mistyped `confidence` errors. Tested at line 251.
- `langgraph_runtime/runtime_impl.rs:229` and
  `anthropic_oauth/runtime_impl.rs:68` — structured triage that violates the
  schema **errors** ("triage JSON violated schema"). Truncated responses
  **error** ("refusing to synthesize a verdict",
  `runtime_impl.rs:236-241`). Empty text **errors**.
- `verify_finding_input.rs` / `verify_exploit_tool.rs` input parsers reject
  mistyped `fingerprint`, `passes`, `mcps`, `timeoutMs` rather than defaulting.

So the "verdict = yes-string-instead-of-bool" case the audit brief worried
about is handled correctly **in the verify-finding path**. The leaks are in the
*normalization* and *proof-state* layers that surround it, and in the loose
JSON-extraction fallback used by the auditor path.

---

## Findings — ranked worst-direction first

### F1 — Model-declared `staticProofState` trusted without verification (TOWARD-CONFIRMED)

- **File:line:** `crates/kuzushi-core/src/capabilities/agentic_sast/application/normalize_findings.rs:97`
  ```rust
  } else if let Some(state) = whitebox_static_proof_state_from_input(&raw_item)? {
      finding.set_static_proof_state(state);
  }
  ```
  via `proof/whitebox_policy/whitebox_static_proof_state_from_input.rs:3-19`.
- **Trigger:** the `whitebox_static` flag is `false` and the model's finding
  object carries `"staticProofState": "statically_confirmed"` (a valid enum
  string). `whitebox_static_proof_state_from_input` only rejects a *non-string*;
  any valid enum string — including the confirmed state — is accepted verbatim
  and written onto the finding.
- **Direction:** **TOWARD-CONFIRMED.** In this branch the citation-validation
  pipeline (`validate_agentic_whitebox_static_claim`, which requires verified
  source/sink/path citations before allowing `StaticallyConfirmed`) is
  **skipped entirely**. The model self-certifies "statically confirmed" and the
  finding keeps that proof state with zero code-citation checking. This is the
  single clearest break of "confirmed only when a verification step ran."
- **Logged?** No. Silent — no note that a self-declared confirmed state bypassed
  validation.
- **Fix:** never let a self-reported `statically_confirmed` (or any
  above-`SignalOnly`) state through the non-whitebox branch. Either force it
  through `validate_agentic_whitebox_static_claim` regardless of the flag, or
  clamp model-supplied states to at most `NeedsRuntimeEvidence` and log that the
  claim was downgraded because no validator ran.

### F2 — Loose "balanced-brace" JSON extraction can lift a verdict object out of the model's reasoning (TOWARD-EITHER, silent)

- **File:line:** `crates/kuzushi-core/src/structured_output/parse_json_value_from_agent_text.rs:66-78`
  (`parse_balanced_agent_json`) and `:104-118`
  (`append_reversed_balanced_candidates`), reached via
  `try_parse_typed_from_agent_text` (`:164-169`).
- **Trigger:** the model emits no clean structured field and no fenced block, so
  the parser walks every balanced `{…}` in the *entire* response — reasoning
  included — and returns the first that deserializes into the target type
  (candidates are reversed, so the **last** balanced object in the text wins).
  If the final answer is prose but an earlier/later reasoning step contains a
  stray `{"triggerable": true, ...}`-shaped object, that object becomes the
  verdict.
- **Direction:** **TOWARD-EITHER**, and that is the problem — the extracted
  object is not guaranteed to be the model's *final* verdict. It can be more
  confirmed than the conclusion the model actually reached.
- **Logged?** No, and worse: `parse_json_value_from_agent_text` (`:3-5`)
  **discards the `strategy`** (`Direct` vs `BalancedObject` vs …). So the one
  signal that would tell an operator "this verdict was scraped out of reasoning
  by the brace-walker, not read from a clean field" is thrown away before the
  verdict is built. `try_parse_typed_from_agent_text` likewise returns only
  `Option<T>`.
- **Fix:** thread `JsonExtractionStrategy` up to the verdict layer and record it
  on the outcome / in a trace line; treat `BalancedObject`/`BalancedArray`
  extraction as low-trust (e.g. force `needs_review` or require a repair pass)
  rather than accepting it as if it were a clean structured field.

### F3 — Deep-auditor loose parse fails to a fixed `NeedsReview @ 0.25` with no trace (TOWARD-NOT-CONFIRMED, silent)

- **File:line:** `crates/kuzushi-core/src/capabilities/deep_auditor/application/parse_vuln_analysis.rs:16-25`
  ```rust
  VulnAnalysis { triggerable: false, rationale: …, confidence: 0.25, evidence: … }
  ```
- **Trigger:** structured output missing/invalid **and** `try_parse_loose_json`
  (F2's extractor) returns `None`.
- **Direction:** TOWARD-NOT-CONFIRMED (safe: `triggerable:false`). But it is a
  *manufactured verdict* — a concrete `0.25` confidence and a `false` triggerable
  presented identically to a real model verdict.
- **Logged?** Partially. The raw text is stuffed into `rationale`, so an
  operator *reading the finding* can see it, but there is **no trace/log event**
  that a synthesized fallback verdict was emitted, and downstream consensus
  (`run_deep_auditor.rs`) treats this 0.25/false as a real vote.
- **Tested?** **Yes** — `deep_auditor/tests.rs:165`
  `malformed_response_falls_back_to_needs_review`. This is one of the few
  fallbacks with a malformed-input test.
- **Fix:** keep the conservative verdict but emit a distinct
  `trace.step("fallback", …)` / structured marker so the synthesized verdict is
  distinguishable from a model-produced one in audit and in consensus counting.

### F4 — Classifier-gate parse failure scores a neutral `0.5` (TOWARD-CONFIRMED-ish, gate weakening)

- **File:line:** `crates/kuzushi-core/src/capabilities/classifier_gate/application/likely_vuln_classifier.rs:49-54`
  ```rust
  .unwrap_or_else(|| { /* score in the middle */ 0.5 })
  ```
- **Trigger:** the classifier model's structured field is absent/invalid and the
  loose text parse fails.
- **Direction:** **TOWARD-CONFIRMED (gate-weakening).** The in-code comment is
  explicit: "score in the middle so the gate doesn't reject a real bug just
  because the model burped." A `0.5` is above the cold-start floor in the tested
  config, so an *unparseable* classifier response **graduates** the finding into
  the deep auditor as if it were a borderline-real bug. Repeated garbage also
  poisons the quantile estimator via `q.observe(raw)` (`:57-58`), nudging the
  adaptive threshold.
- **Logged?** No log/trace when the fallback fires; `0.5` is observed into the
  quantile exactly like a legitimate score.
- **Tested?** Yes — `classifier_gate/tests.rs:180`
  `unparseable_response_falls_back_to_neutral_score`. Happy path only for the
  quantile-poisoning consequence.
- **Fix:** either fail the score (propagate the error and skip the finding with
  a recorded reason) or emit a fallback score that is **not** fed into
  `q.observe`, plus a trace line. Don't let a parse failure look like a
  borderline-positive signal.

### F5 — `taint-iris` / `agentic-sast` / `carlini-threat-hunt` normalization silently drops all findings on shape mismatch (TOWARD-NOT-CONFIRMED, silent)

- **File:line:**
  - `capabilities/taint_iris/application/normalize_findings.rs:8-15`
  - `capabilities/agentic_sast/application/normalize_findings.rs:9-18`
  - `capabilities/carlini_threat_hunt/application/normalize_findings.rs` (same pattern)
  ```rust
  Value::Object(object) => object.get("findings").cloned()
      .unwrap_or_else(|| Value::Array(Vec::new())),
  ```
- **Trigger:** the model returns a JSON **object that lacks a `findings` key**
  (e.g. it wrapped results under `results`, or emitted a single finding object).
  A top-level non-object/non-array *does* `bail!`, but an object without
  `findings` silently becomes an empty array → zero findings.
- **Direction:** TOWARD-NOT-CONFIRMED (findings vanish). Not a false
  confirmation, but a silent loss of real results that reads as a clean "no
  findings" run.
- **Logged?** No. Indistinguishable from a genuine empty result.
- **Tested?** No malformed-shape test found for these three normalizers (grep
  for `not_object` / `findings must be an array` returns only the `bail!` lines,
  no covering test).
- **Fix:** when the object has neither `findings` nor is itself an array, either
  `bail!` (consistent with the sibling non-object case) or log a warning with the
  observed top-level keys, rather than coercing to empty.

### F6 — Per-field verdict defaults in normalizers keep a finding alive with fabricated metadata (TOWARD-CONFIRMED-ish)

These keep a finding that should arguably be dropped, and assign it a
plausible-looking severity/identity from thin air:

- `capabilities/taint_iris/application/normalize_findings.rs:36-40` — missing
  `severity` ⇒ `agentic_severity("medium")` ⇒ **Medium** (not `Unknown`).
  `:25` missing CWE ⇒ literal `"CWE"`; `:30` missing path ⇒ `"unknown"`.
- `capabilities/agentic_sast/application/normalize_findings.rs:43-47` — missing
  `severity` ⇒ `agentic_severity("WARNING")` ⇒ **Medium**.
- `capabilities/uaf_hunt/application/normalize_findings.rs:46-50` + `:92-100`
  — missing/unrecognized `severity` ⇒ `severity_from_label` **`_ => High`**.
  This is the most aggressive: an *unknown* label becomes **High**.
- `capabilities/systems_hunt/adapters/input_helpers.rs:113-115` +
  `findings/domain/from_semgrep.rs:19-28` — systems-hunt uses `Severity::from_label`
  whose `_ => Unknown` is the safe choice; contrast with uaf-hunt above.
- `scan/engines/exploit_chain/mod.rs:664-671` — `parse_severity` `_ => High`.
- **Direction:** TOWARD-CONFIRMED-ish. Defaulting an unpardeable severity to
  **Medium/High** (rather than `Unknown`) inflates the apparent seriousness of a
  finding whose severity the model never actually stated, and the fabricated
  `"CWE"`/`"unknown"` identity lets it survive dedup/report.
- **Logged?** No.
- **Tested?** No malformed-severity tests found for these normalizers.
- **Fix:** default unknown severity to `Severity::Unknown` (as semgrep/systems-hunt
  already do), and keep the `_ => High`/`_ => Medium` arms only where an explicit
  product decision documents why. Consider dropping-or-flagging findings whose
  file path defaulted to `"unknown"`.

### F7 — `verify_finding_response` / consensus re-read `exploitable` with `unwrap_or(false)` (TOWARD-NOT-CONFIRMED, defensive)

- **File:line:**
  - `verification/adapters/verify_finding_tool.rs:146-155`
    `result.get("exploitable").and_then(Value::as_bool).unwrap_or(false)`
  - `verification/adapters/verify_finding_tool.rs:192-201`
    `verification_proof_snapshot`: `.unwrap_or(json!(false))`,
    `proofLevel … unwrap_or(json!(1))`,
    `proofVerdict … unwrap_or(json!("not_reproduced"))`,
    `confidence … unwrap_or(json!(0.0))`.
  - `verification/adapters/verify_consensus.rs:59-63` `is_exploitable` /
    `:65-67` `confidence_of` both `unwrap_or(false)` / `unwrap_or(0.0)`.
- **Trigger:** these read a **already-normalized** result map, so in the normal
  flow the fields are present (F-result validation guarantees `exploitable`).
  The fallback only bites if a future caller passes an un-normalized blob.
- **Direction:** TOWARD-NOT-CONFIRMED (defaults to not-exploitable / lowest
  proof). Safe *today*, but it is defense-by-default rather than
  assert-by-contract: a refactor that routes raw model output here would
  silently downgrade instead of erroring.
- **Logged?** No.
- **Fix:** low priority. Prefer reading the typed struct, or `debug_assert!` the
  key exists so a contract break in tests is loud.

### F8 — Review-projection derives the stored review verdict with string defaults (TOWARD-NOT-CONFIRMED / dropped)

- **File:line:** `crates/kuzushi-core/src/storage_v3/projection_review.rs:23`
  `let verdict = payload_str(&event.payload, "verdict").unwrap_or("needs_review");`
  and `projection_payload.rs:36-45` `triage_verdict_for_review` whose
  `_ => None` swallows any unrecognized verdict string.
- **Trigger:** a persisted `TriageDecided`/`SuppressionAdded` event whose payload
  is missing `verdict`, or carries a verdict string not in the known set.
- **Direction:** TOWARD-NOT-CONFIRMED. Missing ⇒ `needs_review`; unknown ⇒
  `triage_verdict_for_review` returns `None` so the `triage_verdict` column is
  NULL. A stored **"confirmed"** does map to `true_positive` correctly, so this
  is not a confirmation-inflation bug, but an unrecognized future verdict label
  is silently downgraded to "no triage verdict."
- **Logged?** No — `require_payload_str` exists in the same module and *would*
  error, but the review path deliberately uses the non-`require` variant.
- **Fix:** use `require_payload_str(payload, "verdict")` (already available) so a
  malformed event fails projection loudly, and make `triage_verdict_for_review`
  return a `Result`/log on the `_ =>` arm instead of a silent `None`.

### F9 — `next-step` bridge Final step defaults text to empty; unknown step errors (mostly OK)

- **File:line:** `langgraph_runtime/next_step_bridge.rs:141-154`
  `step_from_bridge_response`: `Some("final") => … text: response.text.unwrap_or_default()`;
  `other => bail!` for an unrecognized/missing step kind.
- **Trigger:** a `final` step with no text field.
- **Direction:** neutral-to-not-confirmed. An empty final answer flows downstream
  as `""`, which the auditor path (F3) then turns into a conservative fallback.
  The genuinely dangerous case — an unknown step kind — **does** `bail!`, which
  is correct.
- **Logged?** The `bail!` path is loud; the `unwrap_or_default()` is silent.
- **Fix:** low priority; consider `bail!` on an empty `final` text so the empty
  verdict is not laundered into a downstream fallback.

---

## Ranked summary table (worst silent direction first)

| # | Location | Expression | Trigger | Direction | Logged? | Malformed test? |
|---|----------|-----------|---------|-----------|---------|-----------------|
| F1 | `agentic_sast/application/normalize_findings.rs:97` (+ `whitebox_static_proof_state_from_input.rs:3`) | `set_static_proof_state(state)` from model-supplied string | non-whitebox branch + model says `"staticProofState":"statically_confirmed"` | **TOWARD-CONFIRMED** — skips citation validation entirely | ❌ | ❌ |
| F2 | `structured_output/parse_json_value_from_agent_text.rs:66-118` (via `:164`) | balanced-brace walk, last object wins; `strategy` discarded at `:3` | no clean field/fence; verdict-shaped object sits in reasoning | **TOWARD-EITHER** (may pick non-final object) | ❌ (strategy dropped) | partial (strategy tests exist, not verdict-provenance) |
| F4 | `classifier_gate/application/likely_vuln_classifier.rs:49-54` | `.unwrap_or_else(|| 0.5)` then `q.observe(raw)` | classifier response unparseable | **TOWARD-CONFIRMED** (graduates finding, poisons quantile) | ❌ | ✅ score only (`tests.rs:180`), ❌ quantile effect |
| F6 | `uaf_hunt/…/normalize_findings.rs:92-100`; `taint_iris/…:36-40`; `agentic_sast/…:43-47`; `exploit_chain/mod.rs:664-671` | `_ => High` / `agentic_severity("WARNING"|"medium")` | missing/unknown severity string | **TOWARD-CONFIRMED-ish** (inflates severity) | ❌ | ❌ |
| F5 | `taint_iris`/`agentic_sast`/`carlini` `normalize_findings.rs:8-15` | `.unwrap_or_else(|| Value::Array(Vec::new()))` | object present but no `findings` key | TOWARD-NOT-CONFIRMED (drops all) | ❌ | ❌ |
| F3 | `deep_auditor/application/parse_vuln_analysis.rs:16-25` | `VulnAnalysis{ triggerable:false, confidence:0.25 }` | structured + loose parse both fail | TOWARD-NOT-CONFIRMED (synthesized) | partial (rationale only) | ✅ (`tests.rs:165`) |
| F8 | `storage_v3/projection_review.rs:23` (+ `projection_payload.rs:36-45`) | `.unwrap_or("needs_review")`; `_ => None` | event missing/unknown `verdict` | TOWARD-NOT-CONFIRMED / dropped | ❌ | ❌ |
| F7 | `verify_finding_tool.rs:146-201`; `verify_consensus.rs:59-67` | `.and_then(as_bool).unwrap_or(false)`, `proofLevel unwrap_or(1)` etc. | un-normalized blob reaches these (not in normal flow) | TOWARD-NOT-CONFIRMED (defensive) | ❌ | n/a (normalized upstream) |
| F9 | `next_step_bridge.rs:141-154` | `text: response.text.unwrap_or_default()` | `final` step with no text | neutral | partial | ❌ |

Reference (NOT defects — correct fail-loud behavior, listed so they aren't
re-flagged): `verify_finding_result.rs:154-176` (bool/f64 required, string
`"yes"` rejected); `runtime_impl.rs:229/236`, `anthropic_oauth/runtime_impl.rs:68/78`
(schema violation and truncation error out).

---

## Missing malformed-input test cases

Paths that have **only happy-path** coverage for the fallback identified above:

1. **F1** — no test that a `whitebox_static=false` run with a model-declared
   `staticProofState:"statically_confirmed"` is refused/downgraded. Add a test
   asserting the finding does **not** end up `StaticallyConfirmed` without
   verified citations.
2. **F2** — no test that a response whose *reasoning* contains a verdict-shaped
   `{…}` while the *final answer* differs does not silently adopt the reasoning
   object; and no test asserting the extraction `strategy` is recorded when a
   non-`Direct` strategy produces the verdict.
3. **F5** — no test for `normalize_taint_iris_findings` /
   `normalize_agentic_sast_findings` / `normalize_carlini…` given an object with
   no `findings` key (e.g. `{"results":[…]}`); assert it errors or warns rather
   than returning zero findings.
4. **F6** — no test for the severity default arms: `uaf_hunt` unknown label →
   currently `High` (assert desired behavior); `taint_iris` missing severity →
   currently `Medium`; `agentic_sast` missing severity → currently `Medium`.
5. **F4** — quantile side effect: no test that an unparseable classifier response
   does **not** perturb the adaptive threshold (the `0.5` fallback score effect on
   `q.observe`), separate from the existing score-only test.
6. **F8** — no test that a persisted review event missing `verdict`, or carrying
   an unknown verdict label, is handled loudly rather than defaulting to
   `needs_review` / NULL.
7. **F6/severity parity** — no test pinning the intended contract difference
   between `Severity::from_label` (`_ => Unknown`) and the ad-hoc `parse_severity`
   variants (`_ => High`); pick one and test it.

---

## Bottom line

The verify-finding verdict deserializer — the literal "was it confirmed" gate —
is sound and fails loud. The real exposure is one tier out:

- **F1** is the only path that can stamp a *confirmed* proof state with no
  verification having run; fix it first.
- **F2/F4/F6** don't fabricate "confirmed" outright but push results *toward*
  higher confidence/severity on malformed input, and none of them leave an audit
  trail.
- Across every finding, the common remediation is the same: on a fallback, emit
  a distinct trace/log event and preserve the extraction *provenance* so a
  synthesized or scraped verdict is never indistinguishable from a cleanly
  parsed one.

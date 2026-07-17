# Token-waste changes — adversarial review + what's next

Reviewer: Fable 5. Scope: the 2026-07-09 token-waste remediation (triage dedup +
verdict-skip, carlini inventory hoist + `query_carlini_actor` refactor, bridge
prompt-caching in `scripts/langgraph-bridge/oauth-models.mjs`). Everything is
uncommitted working-tree state; grounded against the `claude-api` skill's
prompt-caching billing rules (prefix match, ≤4 breakpoints, 1.25× write / ~0.1×
read, per-model minimum cacheable prefix, `cache_read_input_tokens` as the
verification signal).

## TL;DR

- **No correctness defects found** in any of the three changes. Cost math in the
  carlini refactor is byte-identical to the pre-refactor arithmetic across all
  five branches; the dedup key merges only truly-identical fingerprints and fans
  the verdict to every sibling row; the bridge cache breakpoints sit on stable
  prefixes and stay within the 4-breakpoint budget.
- Three **behavioral caveats** (not bugs) worth recording — see §4.
- The known residual is real and dominant: **the Rust runtime request has no
  `cache_control` channel**, so triage and carlini still re-bill their large
  shared prefix over the wire on every call. The bridge caching only helps
  payloads the bridge itself assembles from LangChain history; it cannot help a
  single-shot prompt string the Rust runtime rebuilds fresh per call. Plan in §5.

## Provenance note (what is actually uncommitted)

- **Triage dedup + verdict-skip logic is already committed** (`triage_summary.rs`,
  `with_capacity.rs`, `triage_cost_cap_reached.rs` last changed in
  `9b2f1d4a99` / `c926792cc5`). The only uncommitted triage file is
  `crates/kuzushi-core/src/modules/triage/tests.rs` — 3 new tests that lock in
  the behavior. Reviewed the logic anyway since it is in scope.
- **Carlini hoist + `query_carlini_actor` refactor is uncommitted** (working-tree
  diff on `build_actor_prompt.rs`, `capped_actor_hunts.rs`,
  `query_carlini_actor.rs`, `run_carlini_threat_hunt.rs`, `tests.rs`).
- **Bridge caching is uncommitted** (`oauth-models.mjs` + `oauth-models.test.ts`).

---

## 1. Triage dedup + verdict-skip — CORRECT

Files: `crates/kuzushi-core/src/modules/triage/triage_summary.rs`,
`triage_cost_cap_reached.rs`, `with_capacity.rs` (logic committed);
`tests.rs` (uncommitted tests).

**Dedup key merges only identical fingerprints.** `push_triage_candidate`
(`triage_summary.rs:134`) inserts into a `BTreeSet<String>` keyed on
`finding.fingerprint` and pushes the candidate only on first insert
(`:144`). The fingerprint comes from
`stable_fingerprint_for_tool(tool, rule_id, file_path, title, message)`
(`identity/finding_identity.rs:58`) → `compute_stable_fp_v3` over
`{tool_family, rule_id, normalized(file_path), normalized(rule_id)}`. Two
findings collapse **only** when all of those match. The new test
`distinct_identity_findings_each_get_their_own_triage_call` proves an SQLi vs
XSS pair (different `rule_id` + `file_path`) keeps distinct fingerprints and
each gets its own LLM call. No risk of merging two distinct findings.

**Verdict fan-out reaches every sibling row, byte-identically.**
`persist_triage_outcome` (`triage_cost_cap_reached.rs:136`) calls
`record_auto_triage_for_fingerprint`
(`findings/persistence/open/triage_and_verification.rs:21`), which resolves
**all** finding ids sharing the fingerprint via
`finding_ids_for_fingerprint` and upserts the same `TriageOutcome` to each. The
verdict written to the deduped candidate is the identical value written to every
sibling — the fan-out is at persistence, keyed on the same fingerprint, so the
emitted verdict byte is identical across rows. The new test
`duplicated_findings_triage_once_and_fan_verdict_to_all_rows` asserts 1 LLM call
for 4 duplicates and `TruePositive` on all four scan rows.

**Verdict-skip does not skip anything that a fresh triage would change under the
current fingerprint model.** `push_triage_candidate` skips when
`!retriage && finding_has_review_decision` (`:141`). `finding_has_review_decision`
(`:150`) is true if `finding.triage.is_some()` or a persisted review decision
exists for the identity/id. Because the fingerprint is invariant to line number
and snippet bytes, a re-scan whose *evidence* changed but whose
`{tool, rule_id, file_path, title}` did not will be skipped — **this is the
intended verdict-skip, and `retriage=true` is the documented escape hatch.** See
§4 for the one caveat this implies.

**No ordering dependence.** Dedup is set-insertion order-independent for
*which* candidate survives (first-seen), and the surviving verdict is fanned to
all siblings regardless, so the persisted verdict set is order-invariant. The
`results[]` vector order follows selection order, which is deterministic
(`list_findings` ordering / reference order) — no correctness impact.

## 2. Carlini inventory hoist — CORRECT

Files: `.../application/build_actor_prompt.rs`, `capped_actor_hunts.rs`,
`run_carlini_threat_hunt.rs`, `tests.rs`.

**Every actor still receives the full inventory content.** The hoist renders
`render_untrusted_repo_blocks(&run.inventory)` **once** in
`execute_carlini_threat_hunt_run` (`run_carlini_threat_hunt.rs`) and threads the
resulting `&str` `inventory_block` down through
`run_carlini_actor_hunts` → … → `build_actor_prompt`, which pushes it verbatim
via `append_actor_inventory` (`build_actor_prompt.rs:101`). Previously each actor
re-called `render_untrusted_repo_blocks(inventory)` inside `append_actor_inventory`
— identical output, K reconstructions. The block is a pure function of the
inventory slice (`untrusted.rs:33`), so the single render is byte-for-byte what
each actor got before. The new test
`inventory_is_rendered_once_but_every_actor_still_receives_full_inventory`
records 3 actors and asserts each actor's prompt `contains(&inventory_block)`
plus both files' paths and bodies. **No per-actor delta lost** — the inventory
was always identical across actors; only the reconstruction was removed. The
per-actor-varying parts (`actor_identity_lines`, `append_actor_flows`,
`append_actor_threats`) are untouched.

## 3. `query_carlini_actor` refactor cost accounting — CORRECT (byte-identical)

File: `.../application/query_carlini_actor.rs`. Split into
`run_carlini_actor_with_retry` (initial + truncation-retry) and
`repair_carlini_actor_findings` (structured-output repair). Cost math verified
equal to the pre-refactor inline arithmetic in **all five branches**:

| Branch | Pre-refactor `accumulated_cost` returned | Post-refactor | Equal |
|---|---|---|---|
| no retry (not truncated) | `initial.cost_usd` | `run_…with_retry` returns `(initial, initial.cost_usd)` | ✓ |
| retry ok | `initial + retry` | `(retry, initial + retry)` | ✓ |
| retry err | `initial` (retry dropped) | `(initial, initial)` | ✓ |
| findings early-return | returns `accumulated_cost` as computed above | same, cost passed through unchanged | ✓ |
| repair path | `accumulated_cost + max(costed.cost_usd − response.cost_usd, 0)` | `repair_carlini_actor_findings` computes `response_cost = response.cost_usd`, `repair_only = max(costed.cost_usd − response_cost, 0)`, returns `accumulated_cost + repair_only` | ✓ |

The repair-path invariant is preserved: `parse_or_repair_required_structured_json_with_cost`
reports the response's own cost plus any repair cost, and the code adds only the
**repair-only delta** because `accumulated_cost` already counted the response's
cost (in the retry-ok case that is `initial + retry`; `response` there is the
retry, whose cost is what gets subtracted back out — nets to `initial + retry +
repair`). The stale explanatory comment that used to live at the subtraction site
was correctly moved into `repair_carlini_actor_findings`'s doc comment. No
double-counting, no dropped cost.

## 4. Bridge prompt caching — CORRECT placement, budget respected

File: `scripts/langgraph-bridge/oauth-models.mjs`.

**Three breakpoints, each on a genuinely stable prefix, ≤4 budget always
respected.** Render order is `tools → system → messages`:

1. **Tools** (`anthropicToolDefinitions`, `:296`): breakpoint on the **last**
   tool definition. Tools render first and are fixed for the whole run
   (bound once via `bindTools`), so this caches the entire tools segment. The
   tool list is deterministic per run — no per-call variance. 1 breakpoint.
2. **System** (pre-existing, `claudeCodeIdentitySystemBlocks` →
   `cacheableTextBlock`): breakpoint on the role-specific system text block
   (the identity line stays first + unmarked). 1 breakpoint.
3. **History** (`markHistoryCacheBreakpoint`, `:201`): breakpoint on the last
   content block of the most-recently-appended turn — **only when
   `converted.length >= 2`**. This is exactly the documented multi-turn pattern.
   1 breakpoint.

Each segment contributes at most one breakpoint, so the total is **≤3 < 4** in
every code path — the budget cannot be exceeded. The test
`adds at most three breakpoints and changes nothing but cache markers` proves
`breakpoints === 3` and, via `stripCacheControl`, that the payload is
**byte-identical apart from the `cache_control` markers**.

**The history breakpoint cannot mark a call-to-call-varying block in a way that
wastes a write.** The marked block is the *newest* turn, which is indeed new on
each call — but that is the intended write; the *prefix before it* (the stable
history) is the cache read on the next call. This is the standard pattern from
the skill ("breakpoint on the last content block of the most-recently-appended
turn"), and the ~1.25× premium falls only on the small newest turn. **Single-shot
calls are correctly excluded**: `markHistoryCacheBreakpoint` returns unmarked
when `converted.length < 2`, and `contentWithCacheBreakpoint` returns `undefined`
for empty/whitespace content — so a volatile one-off prompt never pays a
cache-write premium for a prefix that is never reused. Test
`leaves a single-shot user prompt unmarked` confirms.

**Note — carlini and triage are single-shot, so the history breakpoint never
fires for them.** Carlini's `query_carlini_actor` sends one prompt string;
triage sends one finding. Both arrive at the bridge as a single converted
message → unmarked. Their large shared prefix (inventory / system) is exactly
what the history breakpoint cannot reach. This is the crux of §5.

**Behavioral caveats (not defects):**

- **[LOW] Triage verdict-skip is blind to evidence changes under a stable
  fingerprint.** Because `stable_fingerprint_for_tool` excludes line number and
  snippet bytes, a re-scan where the vulnerable code moved or changed but the
  `{tool, rule_id, file_path, title}` tuple did not will reuse the old verdict.
  This is the intended dedup semantics and `retriage=true` overrides it, but it
  is a real "changed evidence, same verdict" window. Document it where operators
  choose between a fresh scan and a re-triage.
- **[INFO] The diff also removed `temperature` from the OpenAI Responses body**
  (`oauth-models.mjs`, the OAuth chat model body). This is a correctness
  fix (the endpoint rejects `temperature`), unrelated to caching; the Anthropic path
  still forwards temperature and a test guards both. No token-waste impact.
- **[INFO] 20-block lookback is safe here.** Each bridge call appends only 1–2
  messages per turn, so the history breakpoint always finds the prior write
  within the 20-block window. No intermediate breakpoints needed at current
  loop shapes; revisit if an agent turn ever appends >20 blocks between calls.

---

## 5. What's next — plumb prompt-caching through the Rust runtime → bridge

### The residual, precisely

`AgentQueryRequest` (`crates/kuzushi-core/src/runtime/domain/agent_query.rs:12`)
carries `system_prompt: String` and `prompt: String` — flat strings, **no
`cache_control` channel**. The bridge (`langgraph-bridge.mjs` →
`oauth-models.mjs`) reconstructs the Anthropic body from those strings on every
call. `systemMessageForRequest` already wraps the *system* prompt in a single
cacheable block (`model.mjs:190`), which is the one existing win. But the large
shared **inventory** (carlini) and the large shared **triage prompt prefix**
ride in `prompt` / the user turn, which the bridge never marks — so every
carlini actor call and every triage call re-bills that prefix at full input
price. The now-single `inventory_block` is the natural cache prefix once a
channel exists.

### Design

**A. Add an opt-in cacheable-prefix marker to the runtime request.**
Files: `crates/kuzushi-core/src/runtime/domain/agent_query.rs`,
`crates/kuzushi-openai/src/langgraph_runtime/bridge_payloads.rs`.

Add a serde-optional field that names a stable prefix to cache, e.g.:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub cacheable_prefix: Option<CacheablePrefix>,
```

where `CacheablePrefix { segment: PrefixSegment, text: String }` and
`PrefixSegment ∈ { System, UserPrefix }`. Keep it `Option` + serde-skip so
existing headless callers and the JSON wire shape are unchanged (same discipline
as the existing `temperature` / `structured_output` optional fields). The caller
sets `text` to the exact bytes it wants cached (the rendered `inventory_block`
for carlini; the shared triage prompt header for triage), and the executor
places that text as the **first** user-content block so the volatile per-call
suffix follows it.

**B. Bridge consumes it.** Files: `scripts/langgraph-bridge/oauth-models.mjs`,
`scripts/langgraph-bridge.mjs`, `scripts/langgraph-bridge/model.mjs`.
When `cacheable_prefix.segment === "user_prefix"`, split the user turn into
`[{type:text, text: prefix, cache_control:{type:"ephemeral"}}, {type:text, text:
suffix}]`. Reuse the existing `cacheableTextBlock` helper. Budget: system(1) +
tools(1) + user-prefix(1) + history(1) = 4 — exactly at the ceiling, so the
user-prefix and history breakpoints must not both fire on the same request
(they won't for single-shot carlini/triage, which have no multi-turn history).
Guard against exceeding 4 with an assertion/count.

**C. Surface `cache_read_input_tokens` back to the cost meter so savings are
observable.** Files: `scripts/langgraph-bridge/oauth-models.mjs`
(`anthropicUsage`, `:362`), `model.mjs` (`usageFromMessage`, `:252`),
`crates/kuzushi-openai/src/anthropic_oauth/response.rs`
(`estimate_cost_usd`, `:26`), `AgentQueryResponse`
(`runtime/domain/response_and_roles.rs:185`).
Today `anthropicUsage` reads only `input_tokens` / `output_tokens` and drops
`cache_read_input_tokens` / `cache_creation_input_tokens`. Plumb both through
`usage_metadata`, add `cache_read_input_tokens` / `cache_creation_input_tokens`
to `AgentQueryResponse`, and price cache reads at ~0.1× and cache writes at
~1.25× in `estimate_cost_usd` so the cost meter reflects the real spend and a
zero cache-read count is visibly diagnosable (per the skill's verification rule:
if `cache_read_input_tokens` stays 0 across repeated identical-prefix calls, a
silent invalidator is at work).

**D. Should triage's shared prompt prefix get the same treatment? Yes.**
The triage system header (`TRIAGE_HEADER` + `TRIAGE_VERDICT_RULES` +
`FALSE_POSITIVE_TAXONOMY`, `crates/kuzushi-openai/src/langgraph_runtime/triage.rs`)
is identical across every finding in a run and is already assembled into the
system prompt — so it *should* already be cached by `systemMessageForRequest`.
Confirm that path fires for the triage runtime (it goes through
`triage_finding_blocking`, a different entry than `query_blocking` — verify it
reaches `systemMessageForRequest`, not a bare string). The bigger triage prize
is the **per-finding user prompt** (see §D-leak below), which the system-prefix
cache does not cover.

### Test strategy

- **Bridge unit tests** (`tests/langgraph-bridge/oauth-models.test.ts`): assert
  a `cacheable_prefix` request produces exactly one extra `cache_control` marker
  on the first user block, total ≤4, and `stripCacheControl(body)` is unchanged
  vs. the un-cached body (byte-identity, mirroring the existing tests).
- **Rust serde round-trip** (`bridge_payloads.rs` tests): `cacheable_prefix`
  absent → wire shape unchanged; present → serializes/deserializes.
- **Usage plumbing** (`crates/kuzushi-openai/src/anthropic_oauth/tests.rs`):
  feed a response with `cache_read_input_tokens` set and assert
  `estimate_cost_usd` applies the ~0.1× read rate and populates the new response
  fields.
- **Carlini integration**: extend the existing recording-runtime test to assert
  the inventory rides in a `cacheable_prefix` (or first cached user block) and is
  byte-identical across actors.

Scope M, risk M (touches the runtime↔bridge contract and cost math — both
guardrailed by no-silent-fallback and CRAP gates), effort M.

### Other still-open leaks from the audit memory

1. **Unbounded `request_blob`/`response_blob` in the triage prompt.** The audit
   flagged the triage prompt as the full pretty-printed `Finding` including
   unbounded HTTP blobs (`kuzushi-openai/langgraph_runtime/triage.rs`). Caching
   the *shared* prefix does nothing for this — the blobs are per-finding and
   volatile, and they inflate the uncached remainder on every call. **Fix:
   truncate `request_blob`/`response_blob` (and any oversized evidence) to a
   bounded head in the triage prompt builder**, mirroring the detector's
   `truncate(..,120)` discipline. Scope S, risk L (prompt-content change; add a
   test that the truncated prompt still cites enough to verify), effort S. This
   is likely the single highest-ROI remaining triage token cut.

2. **Truncation-retry re-sends the full input.** `retry_carlini_with_higher_output_budget`
   (and the generic `structured_output/structured_json_contract.rs` retry path)
   resends the entire prompt to lift the output budget. Once §5A–B land, the
   retry benefits automatically (the cached prefix is read at ~0.1× on the retry
   rather than re-billed at full price) — so **no separate fix; it falls out of
   the caching work.** Verify the retry request preserves byte-identical prefix
   bytes so the cache actually hits. Scope S (verification only), risk L.

3. **Unbounded structural-snippet line in the hunt prompt**
   (`taint_iris_next/.../structural_candidates.rs`) and **`findings:list` embedding
   the full ≤500 Finding vec** (`findings/presentation/reporting/output.rs`) —
   both from the original audit, both independent of this caching work. Bound the
   structural snippet like the detector does; consider a projection for
   `findings:list`. Scope S each, risk L, effort S.

### Top 3 next items (ranked)

1. **Runtime→bridge `cache_control` channel + usage plumbing** (§5A–C, D). The
   dominant residual; unlocks cache-reads for the carlini inventory and makes
   savings observable. Scope M / risk M / effort M.
2. **Bound `request_blob`/`response_blob` (and evidence) in the triage prompt**
   (leak #1). Highest-ROI per-call token cut that caching *cannot* address.
   Scope S / risk L / effort S.
3. **Bound the structural-snippet line in the hunt prompt** (leak #3). Cheap,
   isolated, matches an existing truncation pattern. Scope S / risk L / effort S.

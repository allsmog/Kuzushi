# `chrome-rce` — what's next

Roadmap for the offense module that shipped as PR #34 (V1: 6 rules, 4 detection modes, anchored to verified ITW Chrome RCEs). Ordered by value-to-effort, with honest cost estimates. Do these in order; stop when the appetite drops.

---

## Tier 1 — proves V1 actually works (do these first)

### 1.1 — Real-Chromium smoke test for Rule 1

**Why it matters most.** Rule 1's precision is unproven until it runs on actual Chromium. The fixture tests confirm it fires on shaped C++ but not that the `pattern-not-inside` guard clauses survive contact with real broker code. Without this, we can't claim a confidence level honestly.

**What to do.**
1. Shallow-clone Chromium at the commit *just before* CVE-2025-2783's fix (Chrome 134.0.6998.177, March 25 2025). Find the SHA via `git log --oneline -- chrome/browser/safe_browsing/` or the Chrome releases blog.
2. Run `kuzushi scan <chromium-checkout> --tasks chrome-rce`.
3. Expect Rule 1 to fire on the pre-fix Mojo broker. Note any other findings — those are either real bugs or FPs for tightening.
4. `git checkout <fix-commit>` and re-run. Rule 1 should stop firing on the patched site.
5. Document the exact SHAs in `tests/fixtures/chrome-rce/README.md` so this is reproducible.

**Effort.** ~1-2 hours once Chromium is checked out (the checkout itself is the slow part — `gclient sync` can take 30-60 min).

**Anchor.** CVE-2025-2783, fixed in Chrome 134.0.6998.177.

---

### 1.2 — Retrieve verbatim patch text for the remaining anchor CVEs

**Why it matters.** Of our six rules, only Rules 2 and 3 (libwebp, libvpx) have verbatim pre-fix code in their docstrings. Rules 1, 4, 5 are class-level grounded — the *pattern* is right, but the rules' precision would tighten significantly if we read the actual patches.

**What to do.** For each, find the patch via `chromium-review.googlesource.com` (Chromium gerrit) — the agent had 403 issues last research run, but a logged-in human can pull the diff. Update the docstring + README ledger.

| CVE | Component | Status |
|---|---|---|
| CVE-2025-2783 | Mojo broker (ForumTroll) | class only — get the broker `_impl.cc` patch |
| CVE-2024-4671 | Visuals/compositor UAF | class only — get the receiver-class header patch |
| CVE-2026-4676 | Dawn UAF | class only — get the dispatcher cpp patch |
| CVE-2026-5281 | Dawn UAF (KEV) | class only — get the dispatcher cpp patch |

**Effort.** ~1 hour per CVE if gerrit is accessible. ~2-4 hours if you have to find them via Chromium release notes + commit message search.

---

### 1.3 — Tighten Rule 1's `pattern-not-inside` clauses based on real-Chromium FPs

**Depends on 1.1.** Once we see what FPs Rule 1 produces on real Chromium, the YAML's reject-clause set probably needs to grow. Common forms we don't currently match:

- `if (h.is_valid()) { ... }` — Chromium uses `base::win::ScopedHandle` which has an `is_valid()` method.
- `DCHECK(IsValidHandle(h));` followed by `DuplicateHandle` (DCHECK is the guard).
- Pseudo-handle reject expressed as `h != GetCurrentProcess() && h != GetCurrentThread()`.

**Effort.** Iterative — each FP found in 1.1 takes ~10 min to add a clause for. Probably 5-10 iterations to hit acceptable precision.

---

## Tier 2 — make Rules 2-5 actually run

Right now the content packs (hunt prompts + IRIS seeds) require operators to manually stage them via `THREAT_HUNT_PROMPT` / `TAINT_IRIS_PROMPT`. That's friction. If we want Rules 2-5 to fire automatically when chrome-rce is enabled, we need wrapper DagTools.

### 2.1 — Wrapper DagTools that auto-stage hunt prompts

**What.** Two new DagTools in `src/modules/chrome-rce/rules/`:
- `chrome-rce:dawn-stale-pointer-hunt` — depends on `threat-hunt:run`, sets `THREAT_HUNT_PROMPT` to the Dawn markdown before delegating.
- `chrome-rce:mojo-receiver-uaf-hunt` — same shape for the Mojo prompt.

Both gate on `chrome-rce:review-trigger` output: if the path-watch trigger didn't fire on the relevant directory, skip the hunt entirely. This caps cost — we only pay Opus + max-thinking when a PR actually touches the hot surface.

**Why this is non-trivial.** `threat-hunt:run` is a peer DagTool, not a sub-task. We'd need a DAG dependency model where Rule 4/5 says "I need threat-hunt's output, but with my prompt override." The cleanest way is probably a `runtimePromptOverride` field on `DagContext.upstreamOutputs` that the hunt agent reads — but that's a contract change to `threat-hunt`.

**Effort.** ~2-3 days. Plus: need agreement on the contract change (RELEASING.md note + core-sast.ts update per CLAUDE.md guardrail).

### 2.2 — Wrapper DagTools that auto-stage IRIS seeds

Same shape as 2.1, but for `taint-iris:hunt` and the codec seeds. Same contract-change cost. Slightly easier because IRIS already iterates per-CWE — adding a "per-bug-class" axis is a smaller leap.

**Effort.** ~2-3 days.

---

## Tier 3 — more anchor CVEs in the same module

We dropped these from V1 because the patch text wasn't retrieved or the bug class needed more research. They're real candidates for V1.1 or V1.2.

| Rule | Anchor CVE | Tool | Why deferred |
|---|---|---|---|
| `skia-int-overflow-then-oob` | CVE-2026-3909 (Skia OOB write, ITW + KEV) | likely IRIS | patch text not retrieved |
| `blink-css-paint-worklet-uaf` | CVE-2026-2441 (Blink CSS @property/paint, ITW + KEV) | hunt prompt | patch text not retrieved |
| `protobuf-arena-set-allocated-mismatch` | recurring foot-gun, no single headline CVE | semgrep | not anchored to a single ITW |
| `bazel-rule-shellout` | supply-chain class | semgrep on Starlark | not anchored to a single ITW |
| `gpu-refcount-asymmetric` | CVE-2023-6345 (Skia refcount) | hunt prompt | patch text not retrieved; rule shape needs work |

Each rule is a ~half-day to ~2-day add depending on tool. Do these in order of: (a) is the anchor CVE ITW + KEV-listed, (b) can we retrieve patch text, (c) is there an obvious greppable shape.

---

## Tier 4 — sibling modules using the same pattern

Once `chrome-rce` is proven, the same module pattern (anchor-CVE-driven, tool-per-rule, content-pack) ports to other browsers and high-bounty OSS:

- **`webkit-rce`** — Safari/WebKit. Same model: V8 → JavaScriptCore IR bugs, Mojo → IPC layer (`WebKit2`'s message handlers), Skia/CoreGraphics analogue. Anchor CVEs are public via WebKit security advisories.
- **`firefox-rce`** — Mozilla. SpiderMonkey JIT, IPC over `ipc::Channel`, libpng/libwebp shared with Chromium.
- **`node-native-module-rce`** — Node.js native addons (NAPI / N-API). Anchor: prototype pollution + native heap bugs in popular npm packages with C++ bindings.
- **`kernel-rce-smells`** — Linux + Windows kernel patterns: CVE-2024-1086 (nf_tables), CVE-2024-26925 (netfilter), recurring use-after-free shapes in network stacks. Higher noise, lower confidence per rule.

Each module is ~1-2 weeks to ship a V1 with 3-5 rules, mostly because the research effort dwarfs the implementation effort.

---

## Tier 5 — cross-cutting infrastructure

These pay off across all anchor-CVE-driven modules, not just chrome-rce.

### 5.1 — Bounty-aware triage prompts

When a chrome-rce finding fires, the triage agent should know the rule is anchored to an ITW / KEV-listed CVE and bias toward `needs_review` rather than `fp`. The current triage prompt mentions "verified historical CVE" generically — it should pass the actual anchor CVE + bounty tier (where known) into the prompt so triage can weigh evidence.

**Effort.** ~1 day. Touches `src/modules/chrome-rce/chrome-rce.ts:triageAgentConfig` and the rule metadata structure.

### 5.2 — Fuzz-harness coverage detection

The honest reason these CVEs hit Chromium despite Google's fuzzing infra is often "no fuzz harness existed adjacent to this code." A general feature: scan a repo for IPC entry points / parser entry points / codec entry points and surface those that have no `*_fuzzer.cc` / `*_libfuzzer_test.cc` neighbour.

This is **adjacent** to chrome-rce, not part of it — would live in its own module. But it complements the path-watch trigger nicely: "this Maglev file changed AND has no fuzzer in `v8/test/fuzzilli/` directly exercising it."

**Effort.** ~3-5 days for a V1 covering Chromium / Mozilla / generic patterns.

### 5.3 — Reproducibility ledger

A `tests/fixtures/chrome-rce/cve-anchors.yaml` listing every anchor CVE with: pre-fix SHA, fix SHA, the file the rule is supposed to fire on, expected severity. Tier-1.1's smoke test outputs feed this; subsequent CI smoke tests can verify the rules still fire on those exact SHAs.

**Effort.** ~half day once 1.1 produces the data.

---

## Explicit non-goals

These looked tempting and got rejected during V1 design. Documenting so future-us doesn't re-litigate.

- **A Kuzushi-internal fuzzer.** Google's OSS-Fuzz / ClusterFuzz infra runs at billion-CPU-hour scale on every Chrome surface listed here. We can't compete. (See plan §"Tooling reconsidered".)
- **V8 IR-level rules.** CVE-2024-7965 / CVE-2025-6554 / CVE-2026-3910 need a V8-specific IR analyzer (Maglev representation tracking, Turboshaft type lattice). Building that is weeks of work that mostly duplicates V8's own Turbolizer tooling. Rule 6's path-watch trigger is the right Kuzushi-shaped answer.
- **Static taint across the Mojo interface generator.** A real cross-file taint pass would catch more receiver-UAF bugs, but Mojo's generated code is enormous and the analyzer cost dwarfs the rule's value. Rule 5 stays approximate.
- **Tree-sitter integration.** No tree-sitter in the runtime today (confirmed). Adding it for one rule (Rule 4 ordering) is too much weight for too little; we ship the semgrep approximation instead.

---

## Concrete next-PR shape

If someone picks this up tomorrow, the cleanest next PR is **Tier 1.1 + 1.3 bundled**:

1. Run the smoke test against Chromium pre-CVE-2025-2783.
2. Write down what fires (TPs + FPs).
3. Add 2-5 new `pattern-not-inside` clauses to Rule 1's YAML based on the FPs.
4. Re-run, confirm precision improved.
5. Document the SHAs + the FP tighten in `tests/fixtures/chrome-rce/README.md`.
6. PR title: `chrome-rce: tighten Rule 1 against real-Chromium FPs (smoke at pre-2025-2783)`.

That's the smallest, highest-value next chunk and it's what the V1 actually needs to be honest about precision.

# `chrome-rce` — Chrome / Chromium RCE smell rules

Detection rules anchored to verified historical Chrome / Chromium / Google-OSS RCE CVEs. Each rule cites its anchor CVE so triage and code review have a concrete historical exemplar to compare against.

## V1 scope

| # | Rule | Detection | Anchor CVE |
|---|---|---|---|
| 1 | `chrome-rce:scan` (Mojo broker pseudo-handle reject) | Semgrep YAML, embedded in [`rules/mojo-pseudohandle.ts`](./rules/mojo-pseudohandle.ts) | CVE-2025-2783 (Operation ForumTroll, ITW) |
| 2 | IRIS seed: codec fixed-table vs format-spec | Markdown seed at [`iris-seeds/codec-fixed-table-vs-format-spec.md`](./iris-seeds/codec-fixed-table-vs-format-spec.md) | CVE-2023-4863 (libwebp, ITW) |
| 3 | IRIS seed: codec config-overwrite after init | Markdown seed at [`iris-seeds/codec-config-overwrite-after-init.md`](./iris-seeds/codec-config-overwrite-after-init.md) | CVE-2023-5217 (libvpx, ITW) |
| 4 | Hunt prompt: Dawn server stale-pointer | Markdown prompt at [`hunt-prompts/dawn-server-stale-pointer.md`](./hunt-prompts/dawn-server-stale-pointer.md) | CVE-2026-4676, CVE-2026-5281 (ITW) |
| 5 | Hunt prompt: Mojo receiver UAF | Markdown prompt at [`hunt-prompts/mojo-receiver-uaf.md`](./hunt-prompts/mojo-receiver-uaf.md) | CVE-2024-4671 (ITW) |
| 6 | `chrome-rce:review-trigger` (high-bug-density paths) | DagTool at [`rules/review-trigger.ts`](./rules/review-trigger.ts), data at [`data/hot-paths.ts`](./data/hot-paths.ts) | CVE-2024-7965, CVE-2025-6554, CVE-2026-3910, CVE-2026-4675/4676/5281 |

The split exists because each rule's bug class is best matched by a different tool:
- Closed-form input-validation checks → semgrep.
- Data-flow with format-spec reasoning → IRIS-style LLM-driven CodeQL.
- Reentrancy / lifetime reasoning → deep-semantic-hunt with Opus.
- Path-density review focusing → a meta-rule.

See `/Users/.../plans/help-me-with-the-peaceful-twilight.md` for the full reasoning.

## How to use the rules

### Rule 1 — `chrome-rce:scan` (semgrep)

Runs automatically as part of `kuzushi scan` once the module is registered. Requires a `semgrep` (or compatible `opengrep`) binary on PATH. The rule pack is embedded as TypeScript constants and written to a per-scan tempdir; you do not need to clone any external rule repo.

```sh
kuzushi scan ./chromium --tasks chrome-rce
```

### Rule 6 — `chrome-rce:review-trigger` (path watch)

**Opt-in to diff mode.** Without `--diff-base`, the rule emits no findings. With `--diff-base`, it emits one advisory finding per changed file that matches a known-hot path.

```sh
kuzushi scan ./chromium --tasks chrome-rce --diff-base origin/main
```

Hot-path table is at [`data/hot-paths.ts`](./data/hot-paths.ts). To add a new hot path, add an entry there with the anchor CVE; the test suite will not break.

### Hunt prompts (Rules 4 + 5) — staging via `THREAT_HUNT_PROMPT`

The `threat-hunt:run` DagTool accepts a `THREAT_HUNT_PROMPT` config field that takes either inline text or a path to a `.md` / `.txt` file. The chrome-rce module ships two such markdown prompts under `hunt-prompts/`. To run a hunt seeded with one:

```sh
# In the kuzushi shell — focus on a module first.
> /use threat-hunt
kuzushi/threat-hunt> set THREAT_HUNT_PROMPT ./src/modules/chrome-rce/hunt-prompts/dawn-server-stale-pointer.md
kuzushi/threat-hunt> run target=./chromium
```

Or via `kuzushi run`:

```sh
kuzushi run threat-hunt:run \
  --target ./chromium \
  --THREAT_HUNT_PROMPT ./src/modules/chrome-rce/hunt-prompts/dawn-server-stale-pointer.md
```

Per memory `feedback_threat_hunt_opus.md`, threat-hunt runs on Opus with max thinking effort by default — that's the right model for this kind of reasoning.

### IRIS seeds (Rules 2 + 3) — staging via `TAINT_IRIS_PROMPT`

The `taint-iris:hunt` DagTool accepts a `TAINT_IRIS_PROMPT` config field with the same path-or-inline semantics. The chrome-rce module ships two seed prompts under `iris-seeds/`:

```sh
> /use taint-iris
kuzushi/taint-iris> set TAINT_IRIS_PROMPT ./src/modules/chrome-rce/iris-seeds/codec-fixed-table-vs-format-spec.md
kuzushi/taint-iris> hunt target=./libwebp
```

The IRIS loop will use the seed to generate CodeQL queries iteratively. Per memory `project_iris_taint.md`, IRIS does NOT load static `.ql` files — the LLM authors each query fresh. The seed gives it the bug-class context.

## Honest caveats

- **Rule 1** is the only rule with a self-contained automatic scan. All others require either a diff base (Rule 6) or operator-side staging of the content pack (Rules 2-5). V2 may add wrapper DagTools that auto-stage the prompts.
- **Rules 2-5** require a paid LLM and an external CodeQL binary respectively. Cost can be material for a full Chromium scan; gate them on PR-diff mode for sanity.
- **Rules 2-3** (codec) need a buildable codec library for CodeQL. Without a CodeQL database, IRIS falls back to grep-shaped reasoning, which is closer to the deep-semantic-hunt approach but with a confused mental model. Build the database first.
- **Rule 5** (Mojo receiver UAF) has a known-high false-positive rate. It produces *candidates for review*, not auto-confirmable bugs. Tag findings as `needs_review` until a human can compare against a known-safe pattern.
- **No rule here is a substitute for Google's OSS-Fuzz / ClusterFuzz infrastructure.** Where Kuzushi adds value vs. that is PR-time review focus + checklist surfacing, not finding new bugs in fuzzing-saturated surfaces.

## Adding a new rule

1. **Pick the right tool** for the bug class:
   - Pattern-matchable with little context → semgrep YAML in a new file under `rules/`.
   - Data-flow heavy → IRIS seed prompt under `iris-seeds/`.
   - Lifetime / reentrancy / state-machine reasoning → deep-semantic-hunt prompt under `hunt-prompts/`.
   - Path-watch focusing → entry in `data/hot-paths.ts`.
2. **Anchor it** to at least one verified CVE. If the patch text isn't retrievable, lean toward NOT shipping the rule — the FP cost is too high without a concrete historical exemplar.
3. **Add a test** — either a fixture (for semgrep) or a content-pack presence check (for the markdown packs).
4. **Update the V1 scope table above** so reviewers can find what shipped.

## Anchor CVE ledger

Verified during research (commits, advisories, KEV listings). Sources cited in the planning doc.

| CVE | Component | Class | ITW | Verified |
|---|---|---|---|---|
| CVE-2023-4863 | libwebp | OOB write | ✓ | ✓ patch text retrieved |
| CVE-2023-5217 | libvpx | OOB write via reconfigure | ✓ | ✓ patch text retrieved |
| CVE-2024-4671 | Visuals/compositor | UAF | ✓ | class only |
| CVE-2024-7965 | V8 ARM64 codegen | type confusion | ✓ | class only |
| CVE-2025-2783 | Mojo broker | sandbox escape | ✓ | class only (ForumTroll) |
| CVE-2025-6554 | V8 typer | type confusion | ✓ | class only |
| CVE-2026-3910 | V8 Maglev Phi-Untagging | type confusion | ✓ KEV | class only |
| CVE-2026-4675 | Dawn / WebGL | heap overflow | – | class only |
| CVE-2026-4676 | Dawn / WebGPU | UAF | – | class only |
| CVE-2026-5281 | Dawn / WebGPU | UAF | ✓ KEV | class only |

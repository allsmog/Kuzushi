# Comment-quality assessment — agent-ad41367c12e474dc8

> Historical audit — archived snapshot, not current operator guidance.

Scope: every `*.ts` / `*.tsx` under `src/` (640 files).

## Topline counts

| Bucket | Count |
| --- | --- |
| Total comment lines (`//`, `/*`, `*`) | 14,577 |
| Single-line `//` comments | 3,810 |
| Multi-line block starts `/**` / `/*` | 2,962 |
| Long banner separators `// ----` (>= 40 dashes), pure decoration | 380 |
| Decorative unicode section bars (`// ── label ──`) | 194 |
| In-motion narration phrases (`// previously...`, `// Phase D.5 —`, etc.) | ~12 hits below |
| `TODO` / `FIXME` markers | 1 |
| `stub` / `placeholder` markers in production code | 3 (one true larp; two intentional defensive) |

The codebase has a *lot* of comments, but the vast majority are
high-quality WHY explanations of subtle scheduling, runtime, or UX
behavior. The dominant slop pattern is decorative banner separators
and phase-tagging narration ("Phase D.5 —", "(replaces old)", etc).

## Categories

### 1. DELETE — decorative banner pairs (highest-confidence cleanup)

Pattern: `// ----------` (long dash) wrapping a short label, repeated
hundreds of times. They survive `grep` for navigation but the title
line alone is sufficient. Examples:

- `src/errors.ts:8-10` — `// ---` / `// Category` / `// ---`
- `src/errors.ts:43-45` — `// ---` / `// Subclasses` / `// ---`
- `src/copilot/core.ts:499` — naked separator
- `src/modules/types.ts:58` — naked separator
- `src/modules/host-handles.ts`, `src/modules/registry.ts`,
  `src/modules/mcp-bridge.ts`, `src/copilot/shell.ts`,
  `src/copilot/options.ts`, `src/ui/App.tsx`, etc. — same pattern.

Cleanup applied: drop the two dashed framing lines, keep the label as
a single bare comment. (Empty section labels deleted entirely.)

### 2. DELETE — in-motion narration

CLAUDE.md explicitly bans these. Hits found:

- `src/store.ts:1705` — `// triage stage missed; previously those were
  discarded because verify only...` — narrates the change, not the
  current invariant.
- `src/ui/state.ts:1495` — `// Auto-complete any previously active stage`.
- `src/ui/components/CopilotShell.tsx:171-175` — multi-line block
  starting `// survives ... Previously the mode for the rest...`.
- `src/agents/tasks/diff-review.ts:528` — `// Regression detection —
  check if diff reverts previously-fixed vulnerabilities` (this one
  describes current behavior, KEEP).
- `src/agents/tasks/threat-modeling/randori-artifacts.ts:44` —
  `// Previously this returned null when S4 was missing, which
  discarded...`.
- `src/copilot/shell.ts:3997` — `// Previously the summary went to a
  separate "output" history`.
- `src/ui/plain-renderer.ts:244` — `// Phase D.5 — shell-view +
  pendingPlan + threatModel + diffSince`. Phase tagging is task-tracking
  not architecture; `// Shell-view, plan, threat-model, diff-since
  helpers` is enough.

### 3. DELETE — AI-slop multi-paragraph JSDoc

The codebase has 1,289 multi-line JSDoc blocks. Most are real docs.
The egregious cases are short helpers wrapped in 8+ line ceremony:

- `src/errors.ts:133-140` — `classifyError` 7-line JSDoc; one line
  ("Inspect an unknown error and return its `ErrorCategory`") suffices.
- `src/errors.ts:157-161` — `wrapError` 5 lines; the function is
  16 lines and the name is self-explanatory.

These are localized; broad sweep is risky. Trimmed in the high-
confidence pass; the rest left intact.

### 4. KEEP — non-obvious WHY

These are exactly the comments CLAUDE.md asks for. Representative
examples (not exhaustive):

- `src/agent-runtime/claude.ts:437` — "When thinking is enabled,
  temperature must be 1 (or omitted)." — upstream Anthropic API
  invariant.
- `src/scheduler/rate-limit-registry.ts` — adaptive concurrency
  rationale.
- `src/agent-runtime/enforcement.ts` — model-runtime enforcement
  reasoning (mandatory per CLAUDE.md "Model & runtime safety" section).
- `src/store.ts:595` — "Cache prepared statements by placeholder count.
  Typical calls hit two..." — perf rationale.
- `src/ui/App.tsx:57` — "subprocess spawned during `mode === 'running'`
  could disable raw mode" — Ink lifecycle quirk.
- `src/bus/runtime-forwarding.ts:70` — phase tag rationale.
- `src/copilot/core.ts:691-692` — MCP slug collision rationale.
- `src/ui/primitives/Ratchet.tsx:68` — `ink-testing-library` shim
  rationale.
- `src/agent-runtime/pi-ai.ts:677-679` — known-pattern matching hints.
- `src/modules/define.ts:86-90` — defensive `execute` placeholder that
  throws loudly — intentional, comment explains the bridge contract.
- `src/agent-runtime/execution.ts:130` — sentinel-error contract
  with `executeStructuredAgentQuery`.
- `src/scanners/run-semgrep.ts:79` — filter-before-score invariant.
- All of `src/ui/tokens.ts:1-30` — palette/typography contract that
  guides every UI component.

### 5. Stubs / larp inventory (logic flagged, NOT deleted)

Comment-level cleanup is safe; logic-level deletion belongs to other
agents. Findings:

- **`src/modules/recon/core-recon.ts:83-106`** — `recon:nmap` tool's
  `run()` writes a "placeholder host" because "Real impl would shell
  out and parse." The output string brags `(real nmap execution
  pending wire-up)`. **This is genuine larp** — the tool ships and
  pretends to do recon. Recommend: either gate behind a feature flag
  with an honest "not implemented" return, or wire up real nmap.
- **`src/modules/define.ts:91-99`** — `defineDagTool` injects a
  throwing `execute` until the registry bridge wraps it. Defensive
  placeholder, NOT larp; comment explains the contract.
- **`src/monorepo/cross-module-tracing.ts:343`** —
  `crossesTrustBoundary: false, // TODO: check against threat model
  boundaries`. Single TODO; honest. Leave for the owning agent.

### 6. Decorative unicode banners (`// ── label ──`)

194 occurrences (`src/cli.ts`, `src/operator-context.ts`,
`src/threat-model-renderer.ts`, etc). These are subjective style.
Decision: **leave intact**. They are concentrated in long CLI/
renderer files where they aid navigation, and removing them at scale
would touch ~200 files without clear win. CLAUDE.md does not single
them out.

## Build / test status

After the high-confidence cleanup pass: build + tests rerun (see
final report).

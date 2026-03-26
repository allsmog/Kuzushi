# Scanner Power: LLM Code Graph + Multi-Strategy Analysis

## Context

Kuzushi's per-prompt quality is stronger than AIxCC winners (ATLANTIS, RoboDuck), but the detection architecture has gaps. Of the 6 identified architectural gaps vs AIxCC finalists, 3 are fully implemented (cheap classifier, iterative execution feedback, reflection checkpoints) and 3 are partially implemented. This spec closes the two highest-impact remaining gaps:

1. **LLM-Powered Code Graph** — Deep dataflow tracing via LLM to catch complex cross-file vulnerabilities
2. **Multi-Strategy Analysis** — Multiple analytical approaches per vulnerability class for broader coverage

Together these make Kuzushi find bugs that no single-model, single-strategy scanner can.

---

## Part 1: LLM-Powered Code Graph

### Problem

The current call graph infrastructure is static-only (`call-graph-assist.ts` uses `CodeIntelligenceProvider.getCallers()` with max 5 callers). Reachability check (`reachability-check.ts`) uses LLM but is optional and not wired into the main triage flow. No automated entry-point-to-sink tracing exists.

Real vulnerabilities involve 3-7 files of data flow. Static analysis loses the thread at dynamic dispatch, dependency injection, callbacks, and framework middleware chains. An LLM can reason about these.

### Design

#### Two New Tasks

**Task 1: `code-graph-build`**
- **Type**: `AgentTask<ScanOpts, CodeGraphOutput>`
- **outputKind**: `custom`
- **dependsOn**: `["context-gatherer", "context-enricher", "app-model-build"]`

Builds a persistent code graph in two phases:

- **Phase A (Static Skeleton)**: Use existing `CodeIntelligenceProvider` (getCallers, getCallees, getImportGraph) + `ApplicationModel` from `app-model-build` for entry points + `EnrichedRepoContext` from `context-enricher` for middleware/sanitizer locations.

- **Phase B (LLM Gap-Filling)**: For each entry point in the `ApplicationModel`, dispatch an LLM query to trace the path from entry point to data access layer. The LLM gets: the route/handler definition, the static callee chain, framework hints, and Read/Glob/Grep/GetCallers/GetCallees tools.

The LLM prompt is scoped to a specific tracing question (not "build the complete call graph"):

```
You are a code path tracer for a {framework} application. Given the entry point below,
trace the complete execution path through the codebase to identify all function calls,
middleware, and data transformations between receiving the request and the final side effect.

Entry point: {method} {path} -> {handlerSymbol} ({filePath}:{line})
Framework: {framework}
Middleware chain: {middlewareList}

For each hop, record: file, line, function name, hop kind (middleware/controller/service/data-access),
whether data is transformed/validated/sanitized, and what data flows through.

Stop at: external API calls, database queries, file system operations, process boundaries.
```

Framework-specific guidance modules are prepended based on detected framework (Express, Django, Spring, Rails, Fastify, Koa, NestJS, FastAPI).

**Task 2: `code-graph-enrich`**
- **Type**: `AgentTask<Finding[], Finding[]>`
- **outputKind**: `findings`
- **dependsOn**: `["code-graph-build"]`
- **Replaces**: `call-graph-assist` and `reachability-check`

For each finding above a score threshold:
1. Look up the finding's location in the persisted code graph
2. Run shortest-path from every entry point to the finding's node
3. If no path exists, dispatch a targeted LLM query and add result to graph
4. Annotate the finding with: `graphPath`, `hopsFromEntry`, `sanitizersOnPath`, `reachable`, `entryPoints`

#### Graph Schema (SQLite)

New migration `019_add_code_graph_tables.ts`:

**`code_graph_nodes`**: node_id (PK, deterministic hash), repo, run_id, file_path, start_line, symbol, node_kind (entry-http|middleware|controller|service|data-access|sanitizer|validator|...), framework, metadata_json, confidence (1.0=static, <1.0=LLM-inferred), source (static|llm|hybrid)

**`code_graph_edges`**: edge_id (PK), from_node_id, to_node_id, edge_kind (calls|imports|middleware-chain|callback|promise-chain|event-emit|di-inject|dynamic-dispatch|data-flow|...), data_label, ordinal, confidence, source

**`code_graph_paths`**: path_id (PK), entry_node_id, target_node_id, hop_count, path_node_ids (JSON), path_edge_ids (JSON), has_sanitizer, sanitizer_nodes (JSON), confidence (min across edges)

#### Triage Integration

Graph context injected into triage prompt via `TriageTemplateContext`:

```
## Code Graph Context
This finding is {hopsFromEntry} hops from HTTP handler {method} {path}.
Path: {entryPoint} -> {middleware} -> {controller} -> {service} -> [FINDING] -> {sink}
Sanitizers on path: {sanitizerList}
Data flow: {parameterName} passes through {transformationList}
Reachability: {reachable} ({reason})
```

#### Warm-Starting

When enabled, `code-graph-build` checks existing nodes against file modification times. Only re-traces entry points whose handler files or middleware have changed. Deterministic `node_id` (hash of `repo:filePath:line:symbol`) ensures deduplication.

#### Configuration

```typescript
codeGraphEnabled?: boolean;  // default: false
scannerConfig["code-graph"]: {
  model?: string;              // defaults to config.model
  maxEntryPoints?: number;     // default 50
  maxHopsPerTrace?: number;    // default 15
  maxTurnsPerTrace?: number;   // default 10
  prioritizeNearFindings?: boolean;  // default true
  persistGraph?: boolean;      // default true
  warmStart?: boolean;         // default true
}
```

CLI: `--code-graph` flag to enable.

#### Cross-File Taint Propagation

The LLM prompt includes explicit instructions to follow:
- Module imports and re-exports
- Callback patterns and Promise chains
- Configuration objects and environment variables
- Serialization/deserialization boundaries

#### Risk Mitigations

- **Hallucination**: LLM-inferred nodes have `confidence < 1.0`. Static skeleton is ground truth. Triage prompt includes confidence.
- **Cost explosion**: Budget-bounded (max entry points, max turns). Prioritize near findings. Warm-start.
- **Context limits**: Graph in SQLite, queried at point-of-need. Only the path relevant to a finding goes into triage prompt (5-15 nodes).

---

## Part 2: Multi-Strategy Analysis Framework

### Problem

Each vulnerability class currently runs one analysis strategy — one LLM call with one system prompt. RoboDuck (AIxCC #3) ran 4 analysis modes per vulnerability. Different analytical approaches catch different bug shapes.

### Design

#### Strategy Interface

A lightweight protocol that strategy implementations satisfy. Not an `AgentTask` — strategies are internal to detection tasks, invisible to the orchestrator.

```typescript
interface AnalysisStrategy<TConfig = unknown> {
  readonly id: string;
  readonly kind: "syntactic" | "dataflow" | "reasoning" | "execution";
  readonly displayName: string;
  readonly costTier: number;  // 1=cheap, 10=expensive
  appliesTo(cweIds: string[], repoContext?: RepoContext): boolean;
  run(input: StrategyInput, config: TConfig): Promise<StrategyResult>;
}
```

Each strategy returns `StrategyResult` with findings, confidence, costUsd, and typed evidence.

#### 4 Strategy Types

1. **Syntactic** (costTier: 1) — Pattern matching from `KnowledgeModule.dangerousPatterns` + Semgrep rules. No LLM. Cheapest.
2. **Dataflow** (costTier: 3-5) — Bridge to existing taint-analysis passes + LLM-based source-to-sink tracing.
3. **Reasoning** (costTier: 5-7) — First-principles LLM reasoning about architecture, trust boundaries, auth model, framework defaults.
4. **Execution** (costTier: 8-10) — Bridge to existing PoC harness + executor infrastructure. Most expensive.

#### CWE-to-Strategy Mapping

Per-CWE profiles define which strategies run and their early-exit thresholds:

| CWE | Syntactic | Dataflow | Reasoning | Execution |
|-----|-----------|----------|-----------|-----------|
| CWE-89 (SQLi) | yes (0.95) | yes (0.90) | yes (0.85) | yes |
| CWE-79 (XSS) | yes (0.95) | yes (0.90) | yes | - |
| CWE-918 (SSRF) | - | yes (0.90) | yes (0.85) | yes |
| CWE-862/863 (Auth) | - | - | yes | - |
| CWE-94 (Code Injection) | yes (0.95) | yes (0.90) | yes | yes |
| CWE-502 (Deserialization) | yes (0.90) | yes (0.85) | yes | - |

Threshold values = early exit: if this strategy exceeds this confidence, skip more expensive strategies.

#### Execution Modes

- **Adaptive** (default): Run cheapest first. If confident enough, skip expensive ones. `--multi-strategy`
- **Full**: Run all strategies in parallel. Maximum coverage. `--multi-strategy-full`

#### Result Merging

```
1. Collect findings across all strategies
2. Group by location (same dedup as existing dedup.ts)
3. Per group:
   - Confidence boost: +5% per additional corroborating strategy (cap +15%)
   - Strategy disagreement: if minority found it, flag for review
   - Enrich with CorroboratingSignal from each strategy
4. Deduplicate, return enriched findings
```

Uses existing `CorroboratingSignal` and `EngineProvenance` types — no new concepts in output.

#### Task Integration: `withMultiStrategy()` Wrapper

```typescript
function withMultiStrategy<TInput, TOutput>(
  wrappedTask: AgentTask<TInput, TOutput>,
  profile: CweStrategyProfile,
): AgentTask<TInput, TOutput>
```

Wraps existing detection tasks transparently. Same task ID, same output type. When multi-strategy is off, delegates directly to the wrapped task. Zero breaking changes.

Applied in `createDefaultTaskRegistry`:
```typescript
if (config?.multiStrategyMode !== "off") {
  tasks.register(withMultiStrategy(ssrfDetectionTask, profiles.ssrf));
} else {
  tasks.register(ssrfDetectionTask);
}
```

Composes with ensemble: `withMultiStrategy` wraps the task (strategy-level), ensemble wraps the execution (model-level). Orthogonal axes.

#### Auto-Rule Generation

After a finding is confirmed by 2+ strategies:
1. Extract the pattern (source type, sink type, missing guard) via LLM
2. Generate a Semgrep rule YAML or grep pattern
3. Re-scan the codebase for variants using the generated rule
4. Supplements existing LLM-based variant analysis (cheaper, catches syntactic variants)

#### Cost Controls

| Control | Config Key | Default |
|---------|-----------|---------|
| Global toggle | `multiStrategyMode` | `"off"` |
| Total budget/finding | `multiStrategyBudgetUsd` | `2.0` |
| Per-strategy budget | `multiStrategyPerStrategyBudgetUsd` | `0.50` |
| Strategy timeout | `multiStrategyTimeoutMs` | `60000` |
| Auto-rule gen | `multiStrategyAutoRuleGeneration` | `false` |

#### Configuration

```typescript
multiStrategyMode?: "off" | "adaptive" | "full";
multiStrategyBudgetUsd?: number;
multiStrategyPerStrategyBudgetUsd?: number;
multiStrategyTimeoutMs?: number;
multiStrategyAutoRuleGeneration?: boolean;
multiStrategyRescanWithRules?: boolean;
```

CLI flags: `--multi-strategy`, `--multi-strategy-full`, `--multi-strategy-budget <n>`, `--multi-strategy-auto-rules`

---

## File Structure

### New files

```
src/agents/tasks/code-graph/
  types.ts           -- CodeGraphNode, CodeGraphEdge, CodeGraphPath, CodeGraphOutput, FindingGraphContext
  build.ts           -- code-graph-build task (Phase A static + Phase B LLM)
  enrich.ts          -- code-graph-enrich task (replaces call-graph-assist + reachability-check)
  prompts.ts         -- Framework-specific tracing prompt modules
  store.ts           -- SQLite CRUD for graph tables

src/strategies/
  types.ts           -- AnalysisStrategy, StrategyResult, StrategyInput, StrategyEvidence
  registry.ts        -- StrategyRegistry
  cwe-strategy-map.ts -- CWE_STRATEGY_PROFILES
  executor.ts        -- executeStrategies() with cost controls + early exit
  merge.ts           -- mergeStrategyResults() with corroboration + disagreement detection
  multi-strategy-task.ts -- withMultiStrategy() wrapper
  auto-rule.ts       -- GeneratedRule, generateRule(), rescanWithGeneratedRule()
  syntactic/
    index.ts         -- SyntacticStrategy (KnowledgeModule + Semgrep delegation)
  dataflow/
    index.ts         -- DataflowStrategy (taint-analysis bridge + LLM tracer)
  reasoning/
    index.ts         -- ReasoningStrategy (first-principles prompts per CWE)
  execution/
    index.ts         -- ExecutionStrategy (poc-harness + poc-executor bridge)
```

### Modified files

| File | Change |
|------|--------|
| `src/agents/types.ts` | Add `strategyRegistry?: StrategyRegistry` to `TaskContext` |
| `src/agents/index.ts` | Register code-graph tasks, apply `withMultiStrategy` wrapper |
| `src/types.ts` | Add `codeGraphEnabled`, `CodeGraphConfig`, multi-strategy config fields |
| `src/config/defaults.ts` | Add defaults for new config fields |
| `src/schemas.ts` | Add Zod schemas for new config |
| `src/cli.ts` / `src/cli/commands/scan.ts` | Add CLI flags |
| `src/bus/orchestrator.ts` | Replace `callGraphAssistEnabled` block with `codeGraphEnabled` block |
| `src/bus/workers/scan-worker.ts` | Inject `strategyRegistry` into `TaskContext` |
| `src/prompts/context.ts` | Add `FindingGraphContext` to `TriageTemplateContext` |
| `src/store.ts` | Add migration 019 for graph tables |

---

## Implementation Sequence

### Phase 1: Code Graph Core
1. Type definitions (`src/agents/tasks/code-graph/types.ts`)
2. SQLite migration + store functions (`src/agents/tasks/code-graph/store.ts`)
3. Framework prompt modules (`src/agents/tasks/code-graph/prompts.ts`)
4. `code-graph-build` task
5. `code-graph-enrich` task
6. Config + CLI integration
7. Wire into orchestrator (replace call-graph-assist block)
8. Inject graph context into triage prompts

### Phase 2: Multi-Strategy Framework
9. Strategy types + registry (`src/strategies/types.ts`, `registry.ts`)
10. CWE profiles (`src/strategies/cwe-strategy-map.ts`)
11. Executor with cost controls (`src/strategies/executor.ts`)
12. Result merging (`src/strategies/merge.ts`)
13. `withMultiStrategy` wrapper (`src/strategies/multi-strategy-task.ts`)
14. Config + CLI integration

### Phase 3: Strategy Implementations
15. Syntactic strategy (cheapest, leverages KnowledgeModule + Semgrep)
16. Dataflow strategy (bridge to taint-analysis + LLM tracer)
17. Reasoning strategy (new first-principles prompts per CWE)
18. Execution strategy (bridge to poc-harness + poc-executor)

### Phase 4: Auto-Rule Generation
19. Rule extraction via LLM
20. Semgrep rule generation + rescan
21. Integration with variant analysis

### Phase 5: Testing
22. Unit tests for graph construction and querying
23. Unit tests for strategy framework, executor, and merging
24. Unit tests for each strategy implementation
25. Integration tests for code-graph → triage prompt injection
26. E2E test: scan with `--code-graph --multi-strategy` against Juice Shop

---

## Verification

1. **Unit tests**: `pnpm test` — all new tests in `tests/agents/code-graph/` and `tests/strategies/`
2. **Type check**: `pnpm typecheck` — no type errors
3. **E2E**: Run `kuzushi scan benchmarks/juice-shop/repo --code-graph --multi-strategy --scanners semgrep` and verify:
   - Graph is persisted in `.kuzushi/findings.sqlite3` (code_graph_nodes/edges/paths tables populated)
   - Triage prompts include graph context
   - Findings show strategy corroboration evidence
   - Cost tracking shows per-strategy breakdown
4. **Regression**: Run benchmark harness against Juice Shop, compare TP/FP rates with and without code-graph + multi-strategy
5. **Warm-start**: Run same scan twice, verify second run reuses graph from first

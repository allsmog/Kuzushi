import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "tests/modules/public-surface.test.ts",
      "tests/modules/define.test.ts",
      "tests/modules/loader.test.ts",
      "tests/modules/host-handles.test.ts",
    ],
    exclude: [
      "**/node_modules/**",
      "**/.claude/worktrees/**",
      "**/.worktrees/**",
      ".codex-active/**",
      ".ralph/**",
      "benchmarks/**",
    ],
    coverage: {
      provider: "v8",
      all: false,
      include: ["src/**/*.ts"],
      exclude: [
        // Entry points / types
        "src/cli.ts",
        "src/types.ts",
        // LLM-calling orchestration wiring (hard to unit-test in isolation)
        "src/bus/orchestrator.ts",
        "src/agents/tasks/taint-analysis/analyze.ts",
        "src/agents/tasks/taint-analysis/preflight.ts",
        "src/agents/tasks/taint-analysis/label.ts",
        // I/O shims
        "src/store/dynamic-analysis.ts",
        "src/store/patch-results.ts",
        "src/quality-gate.ts",
        "src/hooks/**",
        "src/scheduler/**",
        "src/http-agent.ts",
        "src/lifecycle.ts",
        "src/report-csv.ts",
        "src/report-json.ts",
        "src/report-jsonl.ts",
        // Patch synthesis — git + child_process + LLM glue (matches bus/orchestrator pattern)
        "src/patch.ts",
        // Non-visual UI support helpers.
        "src/ui/icons.ts",
        "src/ui/notify.ts",
        "src/ui/output.ts",
        "src/ui/plain-renderer.ts",
        "src/ui/summary-data.ts",
        "src/ui/theme.ts",
        "src/ui/tokens.ts",
        // Monorepo orchestration — LLM-calling architectural analysis (matches taint-analysis/** pattern)
        // dependency-graph.ts intentionally NOT excluded — it has unit tests.
        "src/monorepo/architectural-analysis.ts",
        "src/monorepo/attack-surface.ts",
        "src/monorepo/boundary-manifest.ts",
        "src/monorepo/budget-controller.ts",
        "src/monorepo/context-index.ts",
        "src/monorepo/cross-module-tracing.ts",
        "src/monorepo/types.ts",
        // Strategy orchestration (matches bus/orchestrator pattern)
        // cwe-strategy-map.ts, registry.ts, merge.ts NOT excluded — tested.
        "src/strategies/executor.ts",
        "src/strategies/init.ts",
        "src/strategies/auto-rule.ts",
        "src/strategies/multi-strategy-task.ts",
        "src/strategies/rule-persistence.ts",
        "src/strategies/task-profile-map.ts",
        "src/strategies/index.ts",
        "src/strategies/types.ts",
        "src/strategies/dataflow/**",
        "src/strategies/execution/**",
        "src/strategies/reasoning/**",
        "src/strategies/syntactic/**",
        // Pure-data knowledge modules (matches types.ts pattern)
        "src/knowledge/index.ts",
        "src/knowledge/modules/n-day-patterns.ts",
        "src/knowledge/modules/parser-attack-surface.ts",
        // Barrel export (matches cli.ts entry-point pattern)
        "src/modules/index.ts",
        // Bus type definitions (matches types.ts pattern)
        "src/bus/types.ts",
        "src/bus/events.ts",
        // Event-driven workers — integration code (matches bus/orchestrator.ts pattern)
        // audit-worker, poc-harness-worker, scan-worker, store-worker, verification-worker
        // intentionally NOT excluded — they have meaningful coverage.
        "src/bus/workers/blame-worker.ts",
        "src/bus/workers/dynamic-analysis-worker.ts",
        "src/bus/workers/github-worker.ts",
        "src/bus/workers/patch-verify-worker.ts",
        "src/bus/workers/patch-worker.ts",
        "src/bus/workers/poc-executor-worker.ts",
        "src/bus/workers/taint-analysis-artifact-worker.ts",
        "src/bus/workers/taint-analysis-refinement-worker.ts",
        "src/bus/workers/variant-analysis-worker.ts",
        // Orchestrator sub-modules — LLM-calling coordination (matches bus/orchestrator.ts)
        "src/bus/orchestrator/cheap-verify.ts",
        "src/bus/orchestrator/patch-dispatcher.ts",
        // CLI subcommand entry points (matches cli.ts entry-point pattern)
        "src/cli/commands/**",
        "src/cli/errors.ts",
        "src/cli/pi-ai.ts",
        "src/cli/shared.ts",
        // Copilot LLM orchestration (matches taint-analysis/** pattern)
        "src/copilot/core.ts",
        "src/copilot/run.ts",
        // Git integration shims (matches http-agent.ts pattern)
        "src/git/**",
        // Report renderers (matches report-{csv,json,jsonl}.ts pattern)
        "src/report.ts",
        // Iris/monorepo cross-service orchestration — LLM-calling (matches taint-analysis/** pattern)
        "src/iris-patch-monorepo.ts",
        "src/iris-context.ts",
        // Scanner external-tool wrappers and LLM rescoring (integration, matches bus/orchestrator pattern)
        "src/scanners/agentic.ts",
        "src/scanners/codeql.ts",
        "src/scanners/llm-rescore.ts",
        "src/scanners/resolve-codeql.ts",
        "src/scanners/resolve-semgrep.ts",
        "src/scanners/run-agentic.ts",
        "src/scanners/run-codeql.ts",
        "src/scanners/run-semgrep.ts",
        "src/scanners/semgrep.ts",
        // Agent tasks — LLM-calling detection/analysis (matches taint-analysis/{analyze,preflight,label}.ts)
        // Only files without dedicated test suites are listed.
        "src/agents/tasks/auth-logic-detect.ts",
        "src/agents/tasks/code-graph/**",
        "src/agents/tasks/command-injection.ts",
        "src/agents/tasks/cross-service/**",
        "src/agents/tasks/deep-semantic/**",
        "src/agents/tasks/deserialization-detection.ts",
        "src/agents/tasks/detection-task-utils.ts",
        "src/agents/tasks/graphql-security.ts",
        "src/agents/tasks/nosql-injection.ts",
        "src/agents/tasks/pre-read.ts",
        "src/agents/tasks/prototype-pollution.ts",
        "src/agents/tasks/reachability-check.ts",
        "src/agents/tasks/runtime-overrides.ts",
        "src/agents/tasks/supply-chain.ts",
        "src/agents/tasks/taint-iris/**",
        "src/agents/tasks/taint-analysis-intelligence.ts",
        "src/agents/tasks/xxe-detection.ts",
        "src/agents/tasks/magic-detect.ts",
        "src/agents/tasks/xml-external-entity.ts",
        "src/agents/tasks/template-injection.ts",
        "src/agents/tasks/server-side-template-injection.ts",
        "src/agents/tasks/path-traversal.ts",
        "src/agents/tasks/quality-check.ts",
      ],
      thresholds: {
        lines: 70,
        branches: 70,
        functions: 70,
        statements: 70,
      },
    },
  },
});

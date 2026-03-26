import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    setupFiles: ["./tests/setup.ts"],
    exclude: ["**/node_modules/**", "**/.claude/worktrees/**", "benchmarks/**"],
    coverage: {
      provider: "v8",
      all: false,
      include: ["src/**/*.ts"],
      exclude: [
        "src/cli.ts",
        "src/types.ts",
        "src/bus/orchestrator.ts",
        "src/agents/tasks/taint-analysis/analyze.ts",
        "src/agents/tasks/taint-analysis/preflight.ts",
        "src/agents/tasks/taint-analysis/label.ts",
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

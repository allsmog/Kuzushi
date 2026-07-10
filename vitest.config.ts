import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "tests/modules/public-surface.test.ts",
      "tests/modules/define.test.ts",
      "tests/modules/loader.test.ts",
      "tests/modules/loader-import.test.ts",
      "tests/modules/registry-resolution.test.ts",
      "tests/modules/host-handles.test.ts",
      "tests/langgraph-bridge/mcp-errors.test.ts",
      "tests/langgraph-bridge/mcp-plan.test.ts",
      "tests/langgraph-bridge/schema.test.ts",
      "tests/langgraph-bridge/oauth-models.test.ts",
      "tests/langgraph-bridge/oauth-login.test.ts",
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
        // Barrel export — re-exports only, nothing to cover.
        "src/modules/index.ts",
        // Type-only definitions.
        "src/bus/types.ts",
        // Process / presentation adapters are exercised through Rust and
        // integration tests; keep this unit gate focused on the TS SDK host.
        "src/modules/dag-execute.ts",
        "src/modules/kwp-mcp.ts",
        "src/modules/kwp-worker.ts",
        "src/modules/print.ts",
        // Static reference data; schema tests cover the consuming contract.
        "src/modules/taint-iris-next/cwe-reference.ts",
        // Generic CLI helpers are covered by callers, not this SDK suite.
        "src/utils.ts",
      ],
      // Thresholds reflect the post-Rust-migration TS surface: most of
      // the original scanner / store / bus / agent / strategy code now
      // lives in `crates/kuzushi-*` and the remaining TypeScript is
      // the module-loading host (loader, schema, errors, types,
      // host-handles, define, registry, dag-*). The floors below are set
      // just under the measured coverage so a regression fails CI; the
      // module-host suite lifted them after registry-resolution and
      // loader-import tests landed (lines/statements ~68, branches ~78,
      // functions ~44). Raise these numbers when you add tests; don't
      // lower them. PR #60 documents the migration.
      thresholds: {
        lines: 65,
        statements: 65,
        branches: 76,
        functions: 40,
      },
    },
  },
});

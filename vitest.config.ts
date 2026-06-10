import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "tests/modules/public-surface.test.ts",
      "tests/modules/define.test.ts",
      "tests/modules/loader.test.ts",
      "tests/modules/host-handles.test.ts",
      "tests/langgraph-bridge/mcp-plan.test.ts",
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
      ],
      // Thresholds reflect the post-Rust-migration TS surface: most of
      // the original scanner / store / bus / agent / strategy code now
      // lives in `crates/kuzushi-*` and the remaining TypeScript is
      // the module-loading host (loader, schema, errors, types,
      // host-handles, define, dag-*). The 70% bar from before the
      // migration is unreachable until the module host gets a richer
      // test surface; the current floor (lines/statements ~55,
      // functions ~28, branches ~76) is encoded here so a regression
      // below the floor still fails CI. Raise these numbers when you
      // add tests; don't lower them. PR #60 documents the migration.
      thresholds: {
        lines: 50,
        statements: 50,
        branches: 70,
        functions: 25,
      },
    },
  },
});

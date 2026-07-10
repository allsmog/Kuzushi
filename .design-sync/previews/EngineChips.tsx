import { TermFrame, EngineChips } from "@kuzushi/tui-kit";

// The default readiness row — cpg warmed (✓ ready + cost), codeql needs a DB
// build first (○ build), lsp available but off (○ opt-in). The mixed-state axis
// the operator reads before committing a scan.
export function Readiness() {
  return (
    <TermFrame chromeless cols={72}>
      <EngineChips
        cols={72}
        engines={[
          { name: "cpg", state: "ready", cost: "~40s" },
          { name: "codeql", state: "build" },
          { name: "lsp", state: "opt-in" },
        ]}
      />
    </TermFrame>
  );
}

// All oracles warmed — every engine ready with its cost estimate, the state a
// scan fires from with full analysis coverage.
export function AllReady() {
  return (
    <TermFrame chromeless cols={72}>
      <EngineChips
        cols={72}
        engines={[
          { name: "cpg", state: "ready", cost: "~40s" },
          { name: "codeql", state: "ready", cost: "~2m" },
          { name: "lsp", state: "ready", cost: "~8s" },
        ]}
      />
    </TermFrame>
  );
}

/**
 * Verify sub-module — exploitability verification for triaged findings.
 * Currently a stub; Phase 3 will add VERIFY_PROMPT + real wiring.
 */

import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";

const verifyFindingTool: ModuleTool = {
  name: "verify:finding",
  description:
    "Verify exploitability of a triaged finding. Constructs a concrete PoC payload " +
    "and optionally executes it in a sandboxed environment. Returns exploitability " +
    "assessment, PoC payload, attack vector, and proof level.",
  inputSchema: {
    type: "object",
    properties: {
      fingerprint: { type: "string", description: "Finding fingerprint to verify." },
    },
    required: ["fingerprint"],
  },
  headless: true,
  async execute(input: unknown, _ctx: ToolExecutionContext): Promise<ToolResult> {
    const p = input as Record<string, unknown>;
    return {
      ok: true,
      output: `[verify:finding] Verification for "${p.fingerprint}" — implementation pending (Phase 2).`,
      data: { fingerprint: p.fingerprint, status: "pending" },
    };
  },
};

export function createVerifyModule(): CopilotModule {
  return {
    id: "verify",
    displayName: "Exploit Verify",
    category: "offense",
    version: "0.17.2",
    description: "Exploitability verification — PoC construction and sandboxed execution.",
    rank: "good",
    references: [],
    notes: {
      stability: ["stable"],
      reliability: ["first-attempt"],
      sideEffects: ["sandbox execution", "costs LLM tokens"],
    },
    requires: [{ kind: "findings", minCount: 1 }],
    tools: [verifyFindingTool],
  };
}

/**
 * Agentic SAST module — LLM-driven bug hunter wrapped as a CopilotModule.
 *
 * Same shape as the other scanner-plugin wrappers (semgrep, codeql): the
 * DagTool's `run()` delegates to `AgenticPlugin.scan`, the bridge auto-
 * installs a shell-mode `execute()` that re-enters the scan pipeline with
 * `--tasks agentic`.
 *
 * Known limitation: the `AGENTIC_SAST_PROMPT` option exists in the input
 * schema (so the shell / `/prompt edit` UX still surfaces it) but the
 * current `AgenticPlugin.scan` body does not read a per-scan prompt
 * override. Wiring this through would require touching
 * `src/scanners/run-agentic.ts`; it was never wired in the legacy module
 * either, so preserving that behaviour is an explicit non-change.
 */

import { AgenticPlugin } from "../../scanners/agentic.js";
import { defineModule } from "../define.js";
import { severityProperty, targetProperty } from "../sast/shared.js";
import { buildScannerDagTool } from "../scanner-adapter.js";
import type { CopilotModule } from "../types.js";

export function createAgenticSastModule(): CopilotModule {
  const agenticScan = buildScannerDagTool<"agentic-sast">(new AgenticPlugin(), {
    name: "agentic-sast:scan",
    displayName: "Agentic SAST",
    description:
      "Run the agentic detector set (SSRF, SQLi, XSS, command injection, deserialization, " +
      "auth-logic, etc.), with scan-only post-processing.",
    inputSchema: {
      type: "object",
      properties: {
        target: targetProperty,
        severity: severityProperty,
        AGENTIC_SAST_PROMPT: {
          type: "string",
          description:
            "Override the agentic-sast detector prompt. Accepts inline text or a path to .md/.txt.",
          "x-advanced": true,
        },
      },
      required: ["target"],
    },
  });

  return defineModule({
    id: "agentic-sast",
    displayName: "Agentic SAST",
    category: "defense",
    version: "0.17.2",
    description:
      "LLM-driven detectors that reason about data flow and intent rather than pattern-match.",
    rank: "good",
    references: [{ type: "OWASP", value: "Top 10" }],
    notes: {
      stability: ["stable"],
      reliability: ["reliable"],
      sideEffects: ["costs LLM tokens"],
    },
    requires: [{ kind: "snapshot", moduleId: "context", field: "appModel" }],
    tools: [agenticScan],
  });
}

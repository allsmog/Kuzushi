/**
 * Semgrep module — Semgrep/Opengrep scanner wrapped as a single-file CopilotModule.
 *
 * The `semgrep:scan` DagTool is both:
 *   - The DAG node (its `run()` body calls `SemgrepPlugin.scan`, producing
 *     `Finding[]` for the scan orchestrator).
 *   - The shell-facing tool (the bridge auto-installs an `execute()` that
 *     re-enters the scan pipeline filtered to just `semgrep`, giving shell
 *     users the same context gathering + findings persistence they get from
 *     `kuzushi scan --tasks semgrep`).
 *
 * Module config (`taskConfig.semgrep.*`) flows through the DagTool's `init()`
 * to `SemgrepPlugin` to resolve the binary path and `--config` flag. This
 * replaces the old `createNativeFindingTask` wrapper in `src/agents/index.ts`.
 */

import { SemgrepPlugin } from "../../scanners/semgrep.js";
import { defineModule } from "../define.js";
import { severityProperty, targetProperty } from "../sast/schema-fragments.js";
import { buildScannerDagTool } from "../scanner-adapter.js";
import type { CopilotModule } from "../types.js";

export function createSemgrepModule(): CopilotModule {
  const semgrepScan = buildScannerDagTool<"semgrep">(new SemgrepPlugin(), {
    name: "semgrep:scan",
    displayName: "Semgrep",
    description: "Run Semgrep only, with scan-only post-processing and report generation.",
    inputSchema: {
      type: "object",
      properties: { target: targetProperty, severity: severityProperty },
      required: ["target"],
    },
  });

  return defineModule({
    id: "semgrep",
    displayName: "Semgrep",
    category: "defense",
    version: "0.17.2",
    description: "Static-pattern rule scanner backed by Semgrep (p/security-audit by default).",
    rank: "great",
    references: [
      { type: "URL", value: "https://semgrep.dev" },
      { type: "OWASP", value: "SAST" },
    ],
    notes: { stability: ["stable"], reliability: ["fast"], sideEffects: [] },
    tools: [semgrepScan],
  });
}

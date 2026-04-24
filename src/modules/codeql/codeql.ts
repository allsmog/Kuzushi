/**
 * CodeQL module — GitHub's taint-query analyzer wrapped as a CopilotModule.
 *
 * Identical shape to the Semgrep module — both drive a `ScannerPlugin`
 * through the `buildScannerDagTool` adapter. Module config overrides flow
 * to the plugin via `init()` so `taskConfig.codeql.language = "java"` etc.
 * take effect before the first scan.
 */

import { CodeQLPlugin } from "../../scanners/codeql.js";
import { defineModule } from "../define.js";
import { severityProperty, targetProperty } from "../sast/schema-fragments.js";
import { buildScannerDagTool } from "../scanner-adapter.js";
import type { CopilotModule } from "../types.js";

export function createCodeqlModule(): CopilotModule {
  const codeqlScan = buildScannerDagTool<"codeql">(new CodeQLPlugin(), {
    name: "codeql:scan",
    displayName: "CodeQL",
    description: "Run CodeQL only, with scan-only post-processing and report generation.",
    inputSchema: {
      type: "object",
      properties: { target: targetProperty, severity: severityProperty },
      required: ["target"],
    },
  });

  return defineModule({
    id: "codeql",
    displayName: "CodeQL",
    category: "defense",
    version: "0.17.2",
    description: "GitHub's taint-query semantic analyzer. Deeper than pattern scanners; slower.",
    rank: "excellent",
    references: [
      { type: "URL", value: "https://codeql.github.com" },
      { type: "OWASP", value: "SAST" },
    ],
    notes: { stability: ["stable"], reliability: ["reliable"], sideEffects: [] },
    tools: [codeqlScan],
  });
}

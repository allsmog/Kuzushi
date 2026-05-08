/**
 * `iac-scan` — Infrastructure-as-Code static checks.
 *
 * STATUS: scaffold only. The factory below returns a CopilotModule with
 * the right shape (id, displayName, category, tools[]) but the single
 * tool returns a `not-implemented` ToolResult pointing operators at the
 * follow-up PR. The deterministic rule pack (Dockerfile, GitHub
 * Actions, Terraform) is the deliverable for the next iteration; see
 * docs/assessments/new-modules.md §iac-scan.
 *
 * Why ship the scaffold now:
 *   - `defineModule` enforces the `iac-scan:` prefix at compile time, so
 *     the manifest contract is locked in before rule authoring starts.
 *   - The CLI surface (`/use iac-scan`, `kuzushi run iac-scan:scan`) is
 *     reachable, which means doc / help-text wiring lands in this PR
 *     without waiting on the rule pack.
 *   - Subsequent PRs only edit this file + add fixtures + tests; no
 *     follow-up plumbing across `core.ts` / `index.ts`.
 *
 * TODO (next PR):
 *   - Replace the placeholder execute() with three real tools:
 *       iac-scan:dockerfile      — USER root, :latest, COPY .. risks
 *       iac-scan:github-actions  — pull_request_target + checkout PR head,
 *                                  unsafe expression interpolation
 *       iac-scan:terraform       — public S3 buckets, 0.0.0.0/0 ingress,
 *                                  hard-coded credentials
 *   - Fixtures under tests/fixtures/iac-scan/{dockerfile,github-actions,terraform}/.
 *   - Wire iac-scan into createDefaultDagRegistry once a stable rule
 *     pack lands. Until then it remains opt-in via `--load iac-scan`
 *     and the loadCoreSast family.
 */

import { defineModule, defineTool } from "../define.js";
import type { CopilotModule, ExecutionContext, ToolResult } from "../types.js";

const scanTool = defineTool<"iac-scan">({
  name: "iac-scan:scan",
  displayName: "IaC Scan",
  description:
    "Static-analysis pass over IaC manifests (Dockerfile, GitHub Actions, " +
    "Terraform). SCAFFOLD — the rule pack lands in the next PR; this " +
    "tool currently returns a not-implemented ToolResult so the module " +
    "shape can be locked in.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Directory to scan (defaults to the active session target).",
      },
      kind: {
        type: "string",
        enum: ["dockerfile", "github-actions", "terraform", "all"],
        default: "all",
        description: "Restrict the scan to one manifest kind.",
      },
    },
  },
  headless: true,
  rank: "manual",
  async execute(_input: unknown, _ctx: ExecutionContext): Promise<ToolResult> {
    return {
      ok: false,
      output:
        "iac-scan:scan is not yet implemented. " +
        "The rule pack (Dockerfile, GitHub Actions, Terraform) lands in " +
        "the next PR — see docs/assessments/new-modules.md.",
    };
  },
});

export function createIacScanModule(): CopilotModule {
  return defineModule({
    id: "iac-scan",
    displayName: "IaC Scan",
    category: "defense",
    version: "0.0.1",
    description:
      "[scaffold] Deterministic IaC static checks for Dockerfile, GitHub " +
      "Actions, and Terraform. Rule pack lands in a follow-up PR.",
    rank: "manual",
    notes: {
      stability: ["unstable"],
      reliability: ["unreliable"],
      sideEffects: [],
    },
    tools: [scanTool],
    events: {
      produces: ["scan:finding"],
      consumes: [],
    },
    async init() {
      // No-op until the rule pack lands.
    },
    async dispose() {
      // No resources to release.
    },
  });
}

/**
 * Chrome RCE smell-rules module.
 *
 * Ships a small, growing set of detection rules anchored to verified
 * historical Chrome / Chromium / Google-OSS RCE CVEs. Each rule documents
 * the anchor CVE in its `metadata.references` so triage can cite the
 * historical example.
 *
 * Tooling decision (see `/Users/.../plans/help-me-with-the-peaceful-twilight.md`):
 * rules whose detection is a flat code-shape check ship as semgrep YAML;
 * rules that need data-flow or LLM reasoning ship in their own DagTools
 * later (codeql / deep-semantic-hunt). V1 is one semgrep rule:
 *   - chrome-rce-mojo-broker-pseudohandle-reject  (CVE-2025-2783)
 *
 * The module wraps a single ScannerPlugin (`ChromeRcePlugin`) that:
 *   1. resolves the semgrep binary via the shared `resolveSemgrepBinary`
 *      helper (so it picks up the same opengrep/semgrep override the
 *      stock semgrep module uses),
 *   2. writes the embedded YAML rule pack to a tempdir at scan time,
 *   3. invokes `runSemgrep` with that rule pack as the only --config,
 *   4. converts SemgrepResult → Finding with `taskId: "chrome-rce"`.
 *
 * The DagTool is exposed via `buildScannerDagTool` so it gets the same
 * shell/run-mode bridge as the stock `semgrep:scan` and `codeql:scan`.
 */

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import { resolveSemgrepBinary } from "../../scanners/resolve-semgrep.js";
import {
  computeFingerprint,
  runSemgrep,
  type SemgrepOutput,
  type SemgrepResult,
  scoreSemgrepFinding,
} from "../../scanners/run-semgrep.js";
import type {
  Finding,
  ScanContext,
  ScannerPlugin,
  TaskConfig,
  TriageAgentConfig,
} from "../../scanners/types.js";
import type { ScanOpts } from "../../types.js";
import { defineModule } from "../define.js";
import { severityProperty, targetProperty } from "../sast/schema-fragments.js";
import { buildScannerDagTool } from "../scanner-adapter.js";
import type { CopilotModule } from "../types.js";
import { MOJO_PSEUDOHANDLE_YAML } from "./rules/mojo-pseudohandle.js";
import { reviewTriggerDagTool } from "./rules/review-trigger.js";

const TASK_ID = "chrome-rce";

/**
 * The list of rules shipped by this module. Each entry is one semgrep
 * YAML document. They are written to a single tempdir at scan time and
 * passed to semgrep via repeated `--config` flags.
 */
const RULES: ReadonlyArray<{ filename: string; yaml: string }> = [
  { filename: "mojo-pseudohandle.yaml", yaml: MOJO_PSEUDOHANDLE_YAML },
];

export class ChromeRcePlugin implements ScannerPlugin {
  readonly id = TASK_ID;
  readonly displayName = "Chrome RCE smells";

  private scannerBin: string = "semgrep";

  async init(config: TaskConfig): Promise<void> {
    const configuredBinary = asOptionalString(config["binary"]);
    if (configuredBinary) {
      this.scannerBin = configuredBinary;
      return;
    }
    this.scannerBin = await resolveSemgrepBinary();
  }

  async scan(
    repoRoot: string,
    opts: ScanOpts,
    _config: TaskConfig,
    _runtime?: AgentRuntime,
    scanContext?: ScanContext,
  ): Promise<Finding[]> {
    const repoName = path.basename(repoRoot);

    const dir = await mkdtemp(path.join(tmpdir(), "kuzushi-chrome-rce-"));
    try {
      const ruleFiles: string[] = [];
      for (const rule of RULES) {
        const target = path.join(dir, rule.filename);
        await writeFile(target, rule.yaml, "utf8");
        ruleFiles.push(target);
      }

      const output = await runSemgrep(repoRoot, opts, this.scannerBin, ruleFiles, {
        signal: scanContext?.signal,
      });

      return convertFindings(output, repoName, "HEAD");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        "You are a Chrome-RCE-focused security triage agent.",
        "This finding came from a chrome-rce rule pack — each rule is anchored to a verified historical Chrome / Chromium RCE CVE.",
        "These rules trade some false positives for catching the recurring shape of high-bounty bugs.",
        "Cite the anchor CVE from the finding's metadata when you confirm or reject the verdict.",
        "",
        "## Finding",
        `Repo: ${repoName}`,
        `Scanner: ${finding.taskId}`,
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Severity: ${finding.severity}`,
        `Scanner Confidence: ${finding.scannerConfidence}`,
        `Likelihood: ${finding.likelihood}`,
        `Impact: ${finding.impact}`,
        `CWE: ${finding.cwe.join(", ") || "none"}`,
        `Message: ${finding.message}`,
        `Evidence: ${finding.evidence || "none"}`,
        `Fingerprint: ${finding.fingerprint}`,
        "",
        "## Investigation instructions",
        "1. Read the flagged file around the target line.",
        "2. Determine whether the code matches the bug-class shape described in the finding message.",
        "3. Trace whether the suspect input actually reaches the sink with attacker control.",
        "4. Check whether a guard exists in a different form than the rule's pattern-not-inside clauses recognise.",
        "5. Cross-reference the anchor CVE referenced in the finding metadata.",
        "",
        "## Output requirements",
        "Return ONLY a JSON object with:",
        "fingerprint, verdict(tp|fp|needs_review), confidence(0..1), rationale, verification_steps(array), fix_patch(string|null)",
      ].join("\n"),
    };
  }
}

function asOptionalString(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.trim();
}

/**
 * Convert raw semgrep output into Kuzushi Finding[] with `taskId: "chrome-rce"`.
 *
 * Mirrors `scanners/run-semgrep.ts:selectFindings` but rewrites taskId and
 * engineProvenance so downstream UI / triage / dedup correctly attributes
 * the finding to the chrome-rce module rather than the stock semgrep one.
 */
function convertFindings(output: SemgrepOutput, repoName: string, ref: string): Finding[] {
  const results = output.results ?? [];
  const seen = new Map<string, Finding>();
  for (const r of results) {
    const fp = computeFingerprint(repoName, ref, r);
    const score = scoreSemgrepFinding(r);
    const finding = buildFinding(r, fp, score);
    const existing = seen.get(fp);
    if (!existing || score > existing.score) {
      seen.set(fp, finding);
    }
  }
  return [...seen.values()].sort((a, b) => b.score - a.score);
}

function buildFinding(r: SemgrepResult, fingerprint: string, score: number): Finding {
  const extra = r.extra ?? {};
  const meta = extra.metadata ?? {};
  return {
    taskId: TASK_ID,
    fingerprint,
    ruleId: r.check_id,
    filePath: r.path,
    startLine: r.start.line,
    severity: extra.severity ?? "INFO",
    message: extra.message ?? "",
    evidence: normalizeEvidence(extra.lines),
    scannerConfidence: meta.confidence ?? "LOW",
    subcategory: meta.subcategory ?? ["chrome-rce"],
    likelihood: meta.likelihood ?? "LOW",
    impact: meta.impact ?? "LOW",
    cwe: meta.cwe ?? [],
    score,
    proofState: "symbolic_only",
    engineProvenance: [{ kind: "semgrep", detail: "chrome-rce semgrep rule match" }],
  };
}

function normalizeEvidence(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

export function createChromeRceModule(): CopilotModule {
  const scanTool = buildScannerDagTool<"chrome-rce">(new ChromeRcePlugin(), {
    name: "chrome-rce:scan",
    displayName: "Chrome RCE smells",
    description:
      "Scan for the recurring code shapes behind verified high-bounty Chrome / Chromium RCE CVEs. " +
      "V1 ships one rule anchored to CVE-2025-2783 (Mojo broker pseudo-handle reject). More rules land as their detection patterns are validated.",
    inputSchema: {
      type: "object",
      properties: { target: targetProperty, severity: severityProperty },
      required: ["target"],
    },
  });

  return defineModule({
    id: "chrome-rce",
    displayName: "Chrome RCE smells",
    category: "defense",
    version: "0.1.0",
    description: "Detection rules anchored to verified Chrome / Chromium RCE CVEs.",
    longDescription:
      "Each rule cites its anchor CVE so triage and review have a concrete historical exemplar to compare against.",
    rank: "good",
    references: [
      { type: "URL", value: "https://chromereleases.googleblog.com/" },
      { type: "CVE", value: "CVE-2025-2783" },
    ],
    notes: { stability: ["experimental"], reliability: ["fast"], sideEffects: [] },
    tools: [scanTool, reviewTriggerDagTool],
  });
}

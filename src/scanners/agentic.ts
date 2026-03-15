import path from "node:path";
import { attachTaskOutputMeta } from "../task-output-meta.js";
import type { ScanOpts } from "../types.js";
import type { Finding, ScannerConfig, ScannerPlugin, TriageAgentConfig } from "./types.js";
import { runAgentic, selectAgenticFindings } from "./run-agentic.js";

const DEFAULT_MODEL = "anthropic:claude-sonnet-4-6";
const DEFAULT_MAX_FINDINGS = 40;

export class AgenticPlugin implements ScannerPlugin {
  readonly id = "agentic";
  readonly displayName = "Agentic LLM Scanner";

  private model = DEFAULT_MODEL;
  private maxFindings = DEFAULT_MAX_FINDINGS;
  private passes: 1 | 2 = 1;

  async init(config: ScannerConfig): Promise<void> {
    const configuredModel = asOptionalString(config["model"]);
    const configuredMax = asPositiveInt(config["maxFindings"]);

    this.model = configuredModel || DEFAULT_MODEL;
    this.maxFindings = configuredMax ?? DEFAULT_MAX_FINDINGS;
    this.passes = config["passes"] === 2 ? 2 : 1;
  }

  async scan(repoRoot: string, opts: ScanOpts, _config: ScannerConfig): Promise<Finding[]> {
    const repoName = path.basename(repoRoot);
    const output = await runAgentic(repoRoot, opts, this.model, this.maxFindings);
    let findings = selectAgenticFindings(output, repoRoot, repoName, "HEAD");
    let totalCost = output.costUsd ?? 0;

    // Optional second pass: LLM reviews first-pass findings and checks for missed classes
    if (this.passes === 2 && findings.length > 0) {
      const reviewOutput = await runAgentic(
        repoRoot,
        {
          ...opts,
          // Inject first-pass findings summary into the second pass context
          agenticReviewContext: summarizeFindingsForReview(findings),
        } as ScanOpts,
        this.model,
        this.maxFindings,
      );
      const reviewFindings = selectAgenticFindings(reviewOutput, repoRoot, repoName, "HEAD");
      totalCost += reviewOutput.costUsd ?? 0;

      // Merge: second pass findings augment first pass (dedup by fingerprint)
      const merged = new Map<string, Finding>();
      for (const f of findings) merged.set(f.fingerprint, f);
      for (const f of reviewFindings) {
        if (!merged.has(f.fingerprint)) merged.set(f.fingerprint, f);
      }
      findings = [...merged.values()].sort((a, b) => b.score - a.score);
    }

    // Do not apply maxFindings here — the registry's dedupeFindings applies
    // the single final cap across all scanners to avoid double-capping.
    return attachTaskOutputMeta(findings, { costUsd: totalCost });
  }

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        "You are a security verification agent reviewing a finding produced by a prior agentic scan pass.",
        "Do NOT blindly trust the prior analysis; verify and falsify with concrete code evidence.",
        "",
        "## Finding",
        `Repo: ${repoName}`,
        `Scanner: ${finding.scanner}`,
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
        "1. Read relevant files and gather additional context with Read/Glob/Grep.",
        "2. Independently validate dataflow, sanitization, authz, config constraints, and runtime reachability.",
        "3. Focus on verification, not rediscovery. Explicitly call out why prior analysis is correct or mistaken.",
        "4. If uncertain after investigation, use needs_review with conservative confidence.",
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

function summarizeFindingsForReview(findings: Finding[]): string {
  const lines = [
    "## First-pass findings (validate and look for missed classes)",
    `Found ${findings.length} findings in pass 1. Review each for accuracy and identify`,
    "vulnerability classes that were NOT covered. Focus on NEW findings, not re-reporting.",
    "",
  ];
  for (const f of findings.slice(0, 20)) {
    lines.push(`- [${f.severity}] ${f.ruleId} at ${f.filePath}:${f.startLine}: ${f.message.slice(0, 100)}`);
  }
  if (findings.length > 20) {
    lines.push(`... and ${findings.length - 20} more findings.`);
  }
  return lines.join("\n");
}

function asPositiveInt(value: unknown): number | null {
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    if (Number.isFinite(parsed) && parsed > 0) return Math.floor(parsed);
    return null;
  }

  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return null;
  }

  return Math.floor(value);
}

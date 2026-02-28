import path from "node:path";
import type { ScanOpts } from "../types.js";
import type { Finding, ScannerConfig, ScannerPlugin, TriageAgentConfig } from "./types.js";
import { runAgentic, selectAgenticFindings } from "./run-agentic.js";

const DEFAULT_MODEL = "anthropic:claude-sonnet-4-6";
const DEFAULT_MAX_FINDINGS = 20;

export class AgenticPlugin implements ScannerPlugin {
  readonly id = "agentic";
  readonly displayName = "Agentic LLM Scanner";

  private model = DEFAULT_MODEL;
  private maxFindings = DEFAULT_MAX_FINDINGS;

  async init(config: ScannerConfig): Promise<void> {
    const configuredModel = asOptionalString(config["model"]);
    const configuredMax = asPositiveInt(config["maxFindings"]);

    this.model = configuredModel || DEFAULT_MODEL;
    this.maxFindings = configuredMax ?? DEFAULT_MAX_FINDINGS;
  }

  async scan(repoRoot: string, opts: ScanOpts, _config: ScannerConfig): Promise<Finding[]> {
    const repoName = path.basename(repoRoot);
    const output = await runAgentic(repoRoot, opts, this.model, this.maxFindings);
    return selectAgenticFindings(output, repoRoot, repoName, "HEAD", opts.maxFindings);
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

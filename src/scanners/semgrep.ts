import path from "node:path";
import type { ScanOpts } from "../types.js";
import type { Finding, ScannerConfig, ScannerPlugin, TriageAgentConfig } from "./types.js";
import { resolveSemgrepBinary } from "./resolve-semgrep.js";
import { runSemgrep, selectFindings } from "./run-semgrep.js";

export class SemgrepPlugin implements ScannerPlugin {
  readonly id = "semgrep";
  readonly displayName = "Semgrep/Opengrep";

  private scannerBin: string = "semgrep";
  private configFlag: string | string[] = "auto";

  async init(config: ScannerConfig): Promise<void> {
    const configuredBinary = asOptionalString(config["binary"]);
    const rawFlag = config["configFlag"];

    if (Array.isArray(rawFlag)) {
      const flags = rawFlag.map((v) => String(v).trim()).filter(Boolean);
      this.configFlag = flags.length > 0 ? flags : "auto";
    } else {
      const configuredFlag = asOptionalString(rawFlag);
      this.configFlag = configuredFlag || "auto";
    }
    if (configuredBinary) {
      this.scannerBin = configuredBinary;
      return;
    }

    this.scannerBin = await resolveSemgrepBinary();
  }

  async scan(repoRoot: string, opts: ScanOpts, _config: ScannerConfig): Promise<Finding[]> {
    const repoName = path.basename(repoRoot);
    const output = await runSemgrep(repoRoot, opts, this.scannerBin, this.configFlag);
    // Do not apply maxFindings here — the registry's dedupeFindings applies
    // the single final cap across all scanners to avoid double-capping.
    return selectFindings(output, repoName, "HEAD");
  }

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        "You are a Semgrep-focused security triage agent.",
        "Semgrep findings come from syntactic/AST pattern matches and can include false positives without full program context.",
        "Investigate thoroughly before deciding verdict.",
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
        "1. Use Read on the flagged file and inspect code around the target line.",
        "2. Use Grep/Glob to find callers, data sources, sinks, validators, sanitizers, and guards.",
        "3. Trace end-to-end dataflow and trust boundaries.",
        "4. Confirm reachability and realistic attacker control.",
        "5. Explicitly explain why Semgrep's pattern signal is correct or a false alarm.",
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

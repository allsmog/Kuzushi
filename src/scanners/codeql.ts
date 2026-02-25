import path from "node:path";
import type { ScanOpts } from "../types.js";
import type { Finding, ScannerConfig, ScannerPlugin, TriageAgentConfig } from "./types.js";
import { resolveCodeQLBinary } from "./resolve-codeql.js";
import { ensureDatabase, runCodeQL, selectFindings } from "./run-codeql.js";

export class CodeQLPlugin implements ScannerPlugin {
  readonly id = "codeql";
  readonly displayName = "CodeQL";

  private codeqlBin = "codeql";
  private dbPath: string | undefined;
  private language: string | undefined;
  private suite: string | undefined;
  private threads: number | undefined;
  private ram: number | undefined;

  async init(config: ScannerConfig): Promise<void> {
    const configuredBinary = asOptionalString(config["binary"]);
    this.dbPath = asOptionalString(config["dbPath"]);
    this.language = asOptionalString(config["language"]);
    this.suite = asOptionalString(config["suite"]);
    this.threads = asPositiveInt(config["threads"]);
    this.ram = asPositiveInt(config["ram"]);

    if (configuredBinary) {
      this.codeqlBin = configuredBinary;
      return;
    }

    this.codeqlBin = await resolveCodeQLBinary();
  }

  async scan(repoRoot: string, opts: ScanOpts, _config: ScannerConfig): Promise<Finding[]> {
    const repoName = path.basename(repoRoot);
    const { dbPath, language } = await ensureDatabase(repoRoot, this.codeqlBin, {
      dbPath: this.dbPath,
      language: this.language,
    });

    const suite = resolveSuite(this.suite, language);
    const sarif = await runCodeQL(dbPath, this.codeqlBin, suite, {
      threads: this.threads,
      ram: this.ram,
    });

    return selectFindings(sarif, repoName, "HEAD", opts.maxFindings);
  }

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        "You are a CodeQL-focused security triage agent.",
        "CodeQL findings are produced from semantic dataflow/taint analysis and usually have higher baseline quality than pattern-only findings.",
        "Still verify carefully: implicit guards, runtime type narrowing, and framework-specific sanitization can invalidate a result.",
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
        "1. Trace the full source-to-sink flow in code, including inter-procedural hops.",
        "2. Validate attacker control, reachability, and realistic execution paths.",
        "3. Check sanitization/encoding/validation and type narrowing at each hop.",
        "4. Confirm whether framework guards, middleware, or policy checks block exploitation.",
        "5. Explain clearly why the CodeQL path is exploitable, not exploitable, or still ambiguous.",
        "",
        "## Output requirements",
        "Return ONLY a JSON object with:",
        "fingerprint, verdict(tp|fp|needs_review), confidence(0..1), rationale, verification_steps(array), fix_patch(string|null)",
      ].join("\n"),
    };
  }
}

function resolveSuite(configuredSuite: string | undefined, language: string): string {
  if (!configuredSuite) {
    return `${language}-security-extended.qls`;
  }

  if (configuredSuite.includes("/") || configuredSuite.includes(":") || configuredSuite.includes(".")) {
    return configuredSuite;
  }

  return `${configuredSuite}.qls`;
}

function asOptionalString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed || undefined;
}

function asPositiveInt(value: unknown): number | undefined {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 1) {
    return undefined;
  }

  return Math.floor(numeric);
}

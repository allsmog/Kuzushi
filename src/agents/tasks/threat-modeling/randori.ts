/**
 * Randori threat model task — runs the Randori PASTA plugin (S1-S4) via
 * Claude Code subprocess, reads the structured artifacts, and converts
 * them to Kuzushi's ThreatModelDocument format.
 *
 * Sole threat model provider — powered by the @kuzushi/randori-plugin dependency.
 */
import { createHash } from "node:crypto";
import path from "node:path";
import { createLogger } from "../../../logger.js";
import { scoreFindingMetadata } from "../../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../../scanners/types.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { toErrorMessage } from "../../../utils.js";
import type { AgentTask } from "../../types.js";
import { resolveTaskAllowedTools } from "../runtime-overrides.js";
import { convertRandoriToThreatModel } from "./randori-adapter.js";
import { mergeRandoriStageOutputs, readRandoriArtifacts } from "./randori-artifacts.js";
import { resolveRandoriPluginPath } from "./resolve-randori.js";
import { resolveThreatModelConfig, type StrideThreat, type ThreatModelDocument } from "./types.js";

const log = createLogger({ stage: "threat-model-randori" });

const IMPACT_TO_SEVERITY: Record<string, string> = {
  critical: "ERROR",
  high: "ERROR",
  medium: "WARNING",
  low: "INFO",
};

function buildScopePrompt(maxElements: number, outputDir: string): string {
  return [
    "You are running a PASTA threat model analysis on the current repository.",
    "",
    "Run stages: s1, s2, s3",
    "",
    `Write the output JSON to the ${outputDir}/ directory:`,
    "- Stage S1: Write pasta-s1.json (business objectives and security requirements)",
    "- Stage S2: Write pasta-s2.json (technical scope — components, actors, data flows)",
    "- Stage S3: Write pasta-s3.json (DFD, trust boundaries, entry points) and dfd.mmd",
    "",
    `Include up to ${maxElements} DFD elements in the technical scope.`,
    "",
    "Explore the codebase thoroughly using Glob, Grep, and Read.",
    "Ground every DFD element in actual code, not theoretical architecture.",
  ].join("\n");
}

function buildStridePrompt(maxThreats: number, outputDir: string): string {
  return [
    "You are running Stage S4 of a PASTA threat model analysis.",
    "",
    `Read the prior stage outputs from ${outputDir}/pasta-s1.json, pasta-s2.json, pasta-s3.json, and dfd.mmd.`,
    "These describe the application's business context, technical scope, and data flow diagram.",
    "",
    `Write ${outputDir}/pasta-s4.json with STRIDE threat scenarios grounded in code evidence.`,
    "",
    "CRITICAL requirements for S4 threat scenarios:",
    "- Every threat MUST have evidence_anchors with file_path, start_line, description",
    "- Use STRIDE categories: spoofing, tampering, repudiation, information-disclosure, denial-of-service, elevation-of-privilege",
    "- Include probability (0-1) and impact (critical/high/medium/low)",
    "- Map to MITRE ATT&CK technique IDs where applicable",
    "- Include OWASP category mapping (e.g., A01, A03)",
    `- Identify up to ${maxThreats} distinct threat scenarios across all STRIDE categories`,
    "",
    "Use the DFD elements and trust boundaries from S3 to identify attack surfaces.",
    "Read the actual source files referenced in the DFD to ground threats in real code.",
    "Focus on the highest-impact threats first.",
  ].join("\n");
}

export const threatModelRandoriTask: AgentTask<
  ScanOpts,
  { document: ThreatModelDocument; findings: Finding[] }
> = {
  id: "threat-model-randori",
  displayName: "Randori PASTA Threat Model",
  outputKind: "threat-model",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<{ document: ThreatModelDocument; findings: Finding[] }> {
    const cfg = resolveThreatModelConfig(context.config);
    const pluginPath = resolveRandoriPluginPath();
    const tag = "[threat-model-randori]";

    // Write artifacts directly into .kuzushi/runs/<runId>/randori-output/
    const artifactDir = path.join(".kuzushi", "runs", context.runId, "randori-output");

    log.info(
      `Starting Randori PASTA analysis (stages=${cfg.randoriStages.join(",")}, model=${cfg.model})`,
    );

    const allowedTools = [...resolveTaskAllowedTools(context), "Write"];
    const baseOpts = {
      cwd: context.repoRoot,
      model: cfg.model,
      allowedTools,
      permissionMode: "dontAsk" as const,
      plugins: [{ type: "local" as const, path: pluginPath }],
    };
    let costUsd = 0;

    // ── Phase 1: S1-S3 (scope, tech decomposition, DFD) ──
    const hasS4 = cfg.randoriStages.includes("s4");
    const scopeStages = hasS4 ? cfg.randoriStages.filter((s) => s !== "s4") : cfg.randoriStages;

    if (scopeStages.length > 0) {
      log.info(`${tag} Phase 1: running stages ${scopeStages.join(",")}`);
      try {
        for await (const message of context.runtime.query({
          prompt: buildScopePrompt(cfg.maxElements, artifactDir),
          options: baseOpts,
        })) {
          if (message.type === "result" && typeof message.totalCostUsd === "number") {
            costUsd += message.totalCostUsd;
          }
        }
      } catch (error) {
        log.warn(`${tag} Phase 1 error: ${toErrorMessage(error)}`);
      }
    }

    // ── Phase 2: S4 (STRIDE threat scenarios with evidence) ──
    if (hasS4) {
      // Only run S4 if S3 produced artifacts to build on
      const scopeArtifacts = readRandoriArtifacts(context.repoRoot, artifactDir);
      if (Object.keys(scopeArtifacts).length > 0) {
        log.info(`${tag} Phase 2: running stage s4 (STRIDE threats)`);
        try {
          for await (const message of context.runtime.query({
            prompt: buildStridePrompt(cfg.maxThreats, artifactDir),
            options: baseOpts,
          })) {
            if (message.type === "result" && typeof message.totalCostUsd === "number") {
              costUsd += message.totalCostUsd;
            }
          }
        } catch (error) {
          log.warn(`${tag} Phase 2 (S4) error: ${toErrorMessage(error)}`);
        }
      } else {
        log.warn(`${tag} Skipping S4 — no scope artifacts from S1-S3`);
      }
    }

    // Read all artifacts (from both phases)
    const artifacts = readRandoriArtifacts(context.repoRoot, artifactDir);
    const merged = mergeRandoriStageOutputs(artifacts);

    if (!merged) {
      log.warn("Randori produced no usable artifacts — falling back to empty threat model");
      const empty: ThreatModelDocument = {
        version: "1.0",
        dfd: { elements: [], trustBoundaries: [] },
        threats: [],
        summary: {
          total: 0,
          bySeverity: {},
          byCategory: {} as ThreatModelDocument["summary"]["byCategory"],
        },
      };
      return attachTaskOutputMeta({ document: empty, findings: [] }, { costUsd });
    }

    const document = convertRandoriToThreatModel(merged);
    if (!document) {
      throw new Error(`${tag} Failed to convert Randori output to ThreatModelDocument`);
    }

    log.info(
      `Converted ${document.threats.length} Randori threats, ${document.dfd.elements.length} DFD elements`,
    );

    const findings = cfg.emitFindings
      ? threatsToFindings(
          document.threats,
          context.repoRoot,
          context.repoName,
          cfg.findingThreshold,
        )
      : [];

    return attachTaskOutputMeta({ document, findings }, { costUsd });
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    const strideMatch = finding.ruleId.match(/^threat-model\/([^/]+)/);
    const strideCategory = strideMatch?.[1] ?? "unknown";

    return {
      prompt: [
        `You are triaging a PASTA threat model finding in "${repoName}".`,
        "",
        `STRIDE Category: ${strideCategory}`,
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Severity: ${finding.severity}`,
        `Message: ${finding.message}`,
        finding.evidence ? `\nEvidence:\n${finding.evidence}` : "",
        "",
        "This finding was identified through PASTA (Process for Attack Simulation and Threat Analysis).",
        "The threat model analyzed the application's data flow diagram, trust boundaries, and attack surface.",
        "",
        "Your task:",
        "1. Read the flagged code and surrounding context to verify the threat is real",
        "2. Check if existing mitigations (input validation, auth checks, TLS) address this threat",
        "3. For offensive/pentest tools: distinguish between DESIGN CHOICES (by_design) and actual bugs",
        "4. Provide a concrete attack scenario if the threat is valid",
      ]
        .filter(Boolean)
        .join("\n"),
    };
  },
};

// ── Finding conversion (mirrors stride.ts) ──

function threatsToFindings(
  threats: StrideThreat[],
  repoRoot: string,
  repoName: string,
  threshold: string,
): Finding[] {
  const thresholdSet = new Set<string>();
  if (threshold === "low") thresholdSet.add("low").add("medium").add("high").add("critical");
  else if (threshold === "medium") thresholdSet.add("medium").add("high").add("critical");
  else if (threshold === "high") thresholdSet.add("high").add("critical");
  else thresholdSet.add("critical");

  const deduped = new Map<string, Finding>();
  let syntheticIndex = 0;
  for (const threat of threats) {
    if (!thresholdSet.has(threat.impact)) continue;
    syntheticIndex += 1;

    const primary =
      threat.affectedFiles.length > 0
        ? {
            filePath: normalizeFilePath(repoRoot, threat.affectedFiles[0].filePath),
            startLine: threat.affectedFiles[0].startLine,
          }
        : { filePath: ".", startLine: syntheticIndex };
    const severity = IMPACT_TO_SEVERITY[threat.impact] || "WARNING";
    const cweList = threat.relatedCwe;
    const cweSegment = cweList.length > 0 ? `/${cweList[0]}` : "";
    const fingerprint = computeFingerprint(repoName, threat);

    const finding: Finding = {
      taskId: "threat-model-randori",
      fingerprint,
      ruleId: `threat-model/${threat.category}${cweSegment}`,
      filePath: primary.filePath,
      startLine: primary.startLine,
      severity,
      message: `[STRIDE/${threat.category}] ${threat.title}: ${threat.description}`,
      evidence: [
        `Attack vector: ${threat.attackVector}`,
        threat.missingMitigations.length > 0
          ? `Missing mitigations: ${threat.missingMitigations.join(", ")}`
          : "",
        ...(threat.evidenceAnchors ?? []).map(
          (a) => `Evidence: ${a.filePath}:${a.startLine} — ${a.description}`,
        ),
      ]
        .filter(Boolean)
        .join(". "),
      scannerConfidence:
        threat.likelihood === "high" ? "HIGH" : threat.likelihood === "medium" ? "MEDIUM" : "LOW",
      subcategory: ["vuln"],
      likelihood: threat.likelihood.toUpperCase(),
      impact: threat.impact === "critical" || threat.impact === "high" ? "HIGH" : "MEDIUM",
      cwe: cweList,
      score: scoreFindingMetadata({
        severity,
        likelihood: threat.likelihood.toUpperCase(),
        impact: threat.impact === "critical" || threat.impact === "high" ? "HIGH" : "MEDIUM",
        subcategory: ["vuln"],
      }),
    };

    const existing = deduped.get(fingerprint);
    if (!existing || finding.score > existing.score) {
      deduped.set(fingerprint, finding);
    }
  }

  return [...deduped.values()];
}

function computeFingerprint(repoName: string, threat: StrideThreat): string {
  const cwes = [...threat.relatedCwe].sort().join(",");
  const files = threat.affectedFiles
    .map((f) => `${f.filePath}:${f.startLine}`)
    .sort()
    .join(",");
  const source = [
    repoName,
    "threat-model-randori",
    threat.category,
    cwes,
    files,
    threat.title,
  ].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

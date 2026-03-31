import { createHash } from "node:crypto";
import path from "node:path";
import { coerceRepoContext } from "../../../repo-context.js";
import { scoreFindingMetadata } from "../../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../../scanners/types.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { RepoContext, ScanOpts } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import { createLogger } from "../../../logger.js";
import type { AgentTask, TaskContext } from "../../types.js";
import { resolveTaskAllowedTools } from "../runtime-overrides.js";
import {
  resolveThreatModelConfig,
  STRIDE_RESPONSE_SCHEMA,
  type DfdElement,
  type EvidenceAnchor,
  type StrideThreat,
  type StrideCategory,
  type ThreatModelDocument,
  type TrustBoundary,
} from "./types.js";

const log = createLogger({ stage: "threat-model-stride" });

const VALID_ELEMENT_TYPES = new Set(["external-entity", "process", "data-store", "data-flow"]);
const VALID_STRIDE_CATEGORIES = new Set<StrideCategory>([
  "spoofing", "tampering", "repudiation",
  "information-disclosure", "denial-of-service", "elevation-of-privilege",
]);
const VALID_IMPACTS = new Set(["critical", "high", "medium", "low"]);
const VALID_LIKELIHOODS = new Set(["high", "medium", "low"]);
const IMPACT_TO_SEVERITY: Record<string, string> = {
  critical: "ERROR",
  high: "ERROR",
  medium: "WARNING",
  low: "INFO",
};

function buildStridePrompt(repoContext: RepoContext | undefined, maxElements: number, maxThreats: number): string {
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        `- Auth patterns: ${repoContext.authPatterns.join(", ") || "unknown"}`,
        `- ORM/DB: ${repoContext.ormOrDb.join(", ") || "unknown"}`,
        `- Entry points: ${repoContext.entryPoints.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  return [
    "You are a threat modeling agent performing STRIDE analysis.",
    "",
    ...contextLines,
    "## Phase 1: System decomposition (Data Flow Diagram)",
    "1. Use Glob/Read to discover entry points, services, data stores, and external dependencies.",
    "2. Look for docker-compose.yml, Kubernetes manifests, Terraform files, etc.",
    "3. Identify DFD elements: external entities, processes, data stores, data flows.",
    "4. Define trust boundaries between zones (internet, DMZ, internal, database).",
    `5. Return at most ${maxElements} DFD elements.`,
    "",
    "## Phase 2: STRIDE per element",
    "For each DFD element, systematically evaluate all 6 STRIDE categories:",
    "- **Spoofing**: Can an entity be impersonated?",
    "- **Tampering**: Can data be modified in transit or at rest?",
    "- **Repudiation**: Can actions go unlogged?",
    "- **Information Disclosure**: Can sensitive data leak?",
    "- **Denial of Service**: Can the element be overwhelmed?",
    "- **Elevation of Privilege**: Can lower-trust code gain higher privileges?",
    "",
    "Cross-reference with actual code (Read/Glob/Grep) to verify if mitigations exist.",
    `Return at most ${maxThreats} threats with concrete affected files.`,
    "",
    "Each threat needs a unique id like 'threat-1', 'threat-2', etc.",
    "Each DFD element needs a unique id like 'elem-1', 'elem-2', etc.",
    "Each trust boundary needs a unique id like 'tb-1', 'tb-2', etc.",
    "",
    "IMPORTANT: Every threat and trust boundary MUST reference at least one specific file path as evidence.",
    "For each threat and trust boundary, provide evidence_anchors: [{file_path, start_line, description}].",
    "Claims without evidence anchors are invalid.",
  ].join("\n");
}

function parseStrideResponse(
  raw: unknown,
  maxElements: number,
  maxThreats: number,
): { elements: DfdElement[]; trustBoundaries: TrustBoundary[]; threats: StrideThreat[] } {
  if (!isRecord(raw)) return { elements: [], trustBoundaries: [], threats: [] };

  const elements = parseElements(raw["elements"], maxElements);
  const trustBoundaries = parseTrustBoundaries(raw["trustBoundaries"]);
  const threats = parseThreats(raw["threats"], maxThreats);

  return { elements, trustBoundaries, threats };
}

function parseElements(value: unknown, max: number): DfdElement[] {
  if (!Array.isArray(value)) return [];
  const out: DfdElement[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const id = asString(item["id"]);
    const type = asString(item["type"]);
    const name = asString(item["name"]);
    if (!id || !name) continue;
    if (!VALID_ELEMENT_TYPES.has(type)) continue;

    out.push({
      id,
      type: type as DfdElement["type"],
      name,
      description: asString(item["description"]) || name,
      trustZone: asString(item["trustZone"]) || "unknown",
      source: asOptString(item["source"]),
      target: asOptString(item["target"]),
      protocol: asOptString(item["protocol"]),
      dataClassification: asOptString(item["dataClassification"]),
    });
    if (out.length >= max) break;
  }
  return out;
}

function parseEvidenceAnchors(value: unknown): EvidenceAnchor[] {
  if (!Array.isArray(value)) return [];
  const out: EvidenceAnchor[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const filePath = asString(item["file_path"]);
    const startLine = Math.max(1, Math.floor(Number(item["start_line"]) || 1));
    const description = asString(item["description"]);
    if (!filePath || !description) continue;
    out.push({ filePath, startLine, description });
  }
  return out;
}

function parseTrustBoundaries(value: unknown): TrustBoundary[] {
  if (!Array.isArray(value)) return [];
  const out: TrustBoundary[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const id = asString(item["id"]);
    const name = asString(item["name"]);
    if (!id || !name) continue;

    const evidenceAnchors = parseEvidenceAnchors(item["evidence_anchors"]);
    out.push({
      id,
      name,
      innerZone: asString(item["innerZone"]) || "internal",
      outerZone: asString(item["outerZone"]) || "external",
      crossingFlows: asStringArray(item["crossingFlows"]),
      ...(evidenceAnchors.length > 0 ? { evidenceAnchors } : {}),
    });
  }
  return out;
}

function parseThreats(value: unknown, max: number): StrideThreat[] {
  if (!Array.isArray(value)) return [];
  const out: StrideThreat[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const id = asString(item["id"]);
    const category = asString(item["category"]);
    const title = asString(item["title"]);
    if (!id || !title) continue;
    if (!VALID_STRIDE_CATEGORIES.has(category as StrideCategory)) continue;

    const impact = asString(item["impact"]);
    const likelihood = asString(item["likelihood"]);

    const evidenceAnchors = parseEvidenceAnchors(item["evidence_anchors"]);
    out.push({
      id,
      elementId: asString(item["elementId"]) || "unknown",
      category: category as StrideCategory,
      title,
      description: asString(item["description"]) || title,
      attackVector: asString(item["attackVector"]) || "unknown",
      preconditions: asStringArray(item["preconditions"]),
      impact: VALID_IMPACTS.has(impact) ? (impact as StrideThreat["impact"]) : "medium",
      likelihood: VALID_LIKELIHOODS.has(likelihood) ? (likelihood as StrideThreat["likelihood"]) : "medium",
      existingMitigations: asStringArray(item["existingMitigations"]),
      missingMitigations: asStringArray(item["missingMitigations"]),
      relatedCwe: asStringArray(item["relatedCwe"]),
      affectedFiles: parseAffectedFiles(item["affectedFiles"]),
      ...(evidenceAnchors.length > 0 ? { evidenceAnchors } : {}),
    });
    if (out.length >= max) break;
  }
  return out;
}

function parseAffectedFiles(value: unknown): Array<{ filePath: string; startLine: number }> {
  if (!Array.isArray(value)) return [];
  return value
    .filter(isRecord)
    .map((item) => ({
      filePath: asString(item["filePath"]),
      startLine: Math.max(1, Math.floor(Number(item["startLine"]) || 1)),
    }))
    .filter((f) => f.filePath);
}

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

    const primary = threat.affectedFiles.length > 0
      ? { filePath: normalizeFilePath(repoRoot, threat.affectedFiles[0].filePath), startLine: threat.affectedFiles[0].startLine }
      : { filePath: ".", startLine: syntheticIndex };
    const filePath = primary.filePath;
    const severity = IMPACT_TO_SEVERITY[threat.impact] || "WARNING";
    const cweList = threat.relatedCwe;
    const cweSegment = cweList.length > 0 ? `/${cweList[0]}` : "";
    const fingerprint = computeFingerprint(repoName, threat);

    const finding: Finding = {
      scanner: "threat-model-stride",
      fingerprint,
      ruleId: `threat-model/${threat.category}${cweSegment}`,
      filePath: primary.filePath,
      startLine: primary.startLine,
      severity,
      message: `[STRIDE/${threat.category}] ${threat.title}: ${threat.description}`,
      evidence: [
        `Attack vector: ${threat.attackVector}`,
        threat.missingMitigations.length > 0 ? `Missing mitigations: ${threat.missingMitigations.join(", ")}` : "",
        ...(threat.evidenceAnchors ?? []).map((a) => `Evidence: ${a.filePath}:${a.startLine} — ${a.description}`),
      ].filter(Boolean).join(". "),
      scannerConfidence: threat.likelihood === "high" ? "HIGH" : threat.likelihood === "medium" ? "MEDIUM" : "LOW",
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
  const files = threat.affectedFiles.map((f) => `${f.filePath}:${f.startLine}`).sort().join(",");
  const source = [repoName, "threat-model-stride", threat.category, cwes, files, threat.title].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

function buildSummary(threats: StrideThreat[]): ThreatModelDocument["summary"] {
  const bySeverity: Record<string, number> = {};
  const byCategory = {} as Record<StrideCategory, number>;

  for (const threat of threats) {
    bySeverity[threat.impact] = (bySeverity[threat.impact] || 0) + 1;
    byCategory[threat.category] = (byCategory[threat.category] || 0) + 1;
  }

  return { total: threats.length, bySeverity, byCategory };
}

export const threatModelStrideTask: AgentTask<ScanOpts, { document: ThreatModelDocument; findings: Finding[] }> = {
  id: "threat-model-stride",
  displayName: "STRIDE Threat Model",
  outputKind: "threat-model",
  dependsOn: ["context-gatherer"],

  async run(_input, context): Promise<{ document: ThreatModelDocument; findings: Finding[] }> {
    const cfg = resolveThreatModelConfig(context.config);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const prompt = buildStridePrompt(repoContext, cfg.maxElements, cfg.maxThreats);
    const runtime = context.runtime;

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[threat-model-stride]";
    log.info(`Starting STRIDE analysis (model=${cfg.strideModel})`);

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model: cfg.strideModel,

          maxOutputTokens: 16384,
          allowedTools: resolveTaskAllowedTools(context),
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: STRIDE_RESPONSE_SCHEMA,
            strict: true,
            retryInvalidStructuredOutput: 2,
          },
        },
      })) {
        if (message.type !== "result") continue;
        if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
          costUsd = message.totalCostUsd;
        }
        if ("result" in message) {
          resultText = message.result;
          structuredOutput = message.structuredOutput;
        }
      }
    } catch (error) {
      throw new Error(`${tag} Agent error: ${toErrorMessage(error)}`);
    }

    const parsed = parseStrideResponse(
      structuredOutput ?? parseJson(resultText, tag),
      cfg.maxElements,
      cfg.maxThreats,
    );

    log.info(`Found ${parsed.elements.length} elements, ${parsed.threats.length} threats`);

    const document: ThreatModelDocument = {
      version: "1.0",
      dfd: { elements: parsed.elements, trustBoundaries: parsed.trustBoundaries },
      threats: parsed.threats,
      summary: buildSummary(parsed.threats),
    };

    const findings = cfg.emitFindings
      ? threatsToFindings(parsed.threats, context.repoRoot, context.repoName, cfg.findingThreshold)
      : [];

    return attachTaskOutputMeta({ document, findings }, { costUsd });
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging a STRIDE threat model finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Evidence: ${finding.evidence}` : "",
        "",
        "This finding represents a threat identified through DFD-based STRIDE analysis.",
        "Verify the threat is realistic given the actual system architecture and existing mitigations.",
      ].filter(Boolean).join("\n"),
    };
  },
};

function parseJson(text: string, tag: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${tag} Invalid JSON output: ${toErrorMessage(error)}`);
  }
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function asOptString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((v) => String(v).trim()).filter(Boolean);
}

export const __strideInternals = {
  buildStridePrompt,
  parseStrideResponse,
  parseEvidenceAnchors,
  threatsToFindings,
  computeFingerprint,
  buildSummary,
};

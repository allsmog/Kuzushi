import { createHash } from "node:crypto";
import path from "node:path";
import { getAgentRuntime } from "../../../agent-runtime/index.js";
import { scoreFindingMetadata } from "../../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../../scanners/types.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { AgentTask, TaskContext } from "../../types.js";
import {
  resolveThreatModelConfig,
  PASTA_RESPONSE_SCHEMA,
  type AttackSimulationDocument,
  type AttackTree,
  type AttackTreeNode,
  type ThreatModelDocument,
} from "./types.js";

function buildPastaPrompt(
  strideThreats: string[],
  upstreamFindings: string[],
  maxTrees: number,
): string {
  const threatList = strideThreats.length > 0
    ? ["## STRIDE threats from upstream", ...strideThreats.map((t) => `- ${t}`), ""]
    : [];

  const findingList = upstreamFindings.length > 0
    ? ["## Upstream scanner findings", ...upstreamFindings.map((f) => `- ${f}`), ""]
    : [];

  return [
    "You are a PASTA (Process for Attack Simulation and Threat Analysis) agent.",
    "Build attack trees that combine individual vulnerabilities into realistic exploitation chains.",
    "",
    ...threatList,
    ...findingList,
    "## Instructions",
    "1. Review all upstream threats and findings.",
    "2. Use Read/Glob/Grep to verify exploitability and chain dependencies.",
    "3. Build attack trees with AND/OR/LEAF nodes representing exploitation steps.",
    "4. For each tree, assign a goal (attacker objective) and overall risk level.",
    "5. Map nodes to MITRE ATT&CK technique IDs where applicable.",
    "6. Reference related findings (fingerprints) and STRIDE threat IDs in nodes.",
    `7. Return at most ${maxTrees} attack trees, prioritized by overall risk.`,
    "",
    "Focus on realistic multi-step attacks that chain 2+ vulnerabilities.",
    "Each tree needs nodes with unique ids like 'node-1', 'node-2', etc.",
  ].join("\n");
}

function collectUpstreamContext(context: TaskContext): { strideThreats: string[]; upstreamFindings: string[] } {
  const strideThreats: string[] = [];
  const upstreamFindings: string[] = [];

  const strideOutput = asStrideTaskOutput(context.upstreamOutputs.get("threat-model-stride"));
  if (strideOutput?.document?.threats) {
    for (const threat of strideOutput.document.threats) {
      strideThreats.push(`[${threat.id}] ${threat.category}: ${threat.title} (impact: ${threat.impact})`);
    }
  }

  for (const [taskId, output] of context.upstreamOutputs.entries()) {
    if (taskId === "threat-model-stride") {
      if (strideOutput?.findings) {
        for (const f of strideOutput.findings) {
          upstreamFindings.push(`[${f.fingerprint.slice(0, 8)}] ${f.ruleId}: ${f.message}`);
        }
      }
      continue;
    }

    if (Array.isArray(output)) {
      for (const item of output) {
        if (isFindingRecord(item)) {
          upstreamFindings.push(`[${item.fingerprint.slice(0, 8)}] ${item.ruleId}: ${item.message}`);
        }
      }
    }
  }

  return { strideThreats, upstreamFindings };
}

function asStrideTaskOutput(
  value: unknown,
): { document: ThreatModelDocument; findings: Finding[] } | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const document = value["document"];
  const findings = value["findings"];
  if (!isThreatModelDocument(document) || !Array.isArray(findings)) {
    return undefined;
  }

  return {
    document,
    findings: findings.filter(isFindingRecord) as Finding[],
  };
}

function isThreatModelDocument(value: unknown): value is ThreatModelDocument {
  return isRecord(value)
    && Array.isArray(value["threats"])
    && isRecord(value["dfd"])
    && isRecord(value["summary"]);
}

function isFindingRecord(value: unknown): value is Finding {
  return isRecord(value)
    && typeof value["fingerprint"] === "string"
    && typeof value["ruleId"] === "string"
    && typeof value["message"] === "string";
}

function parsePastaResponse(raw: unknown, maxTrees: number): AttackTree[] {
  if (!isRecord(raw) || !Array.isArray(raw["trees"])) return [];

  const trees: AttackTree[] = [];
  for (const item of raw["trees"] as unknown[]) {
    if (!isRecord(item)) continue;
    const tree = normalizeTree(item);
    if (!tree) continue;
    trees.push(tree);
    if (trees.length >= maxTrees) break;
  }

  return trees;
}

function normalizeTree(item: Record<string, unknown>): AttackTree | null {
  const goal = typeof item["goal"] === "string" ? item["goal"].trim() : "";
  if (!goal) return null;

  const overallRisk = typeof item["overallRisk"] === "string"
    && ["critical", "high", "medium", "low"].includes(item["overallRisk"])
    ? (item["overallRisk"] as AttackTree["overallRisk"])
    : "medium";

  const rootNode = isRecord(item["rootNode"])
    ? normalizeNode(item["rootNode"])
    : null;

  if (!rootNode) return null;

  return { goal, rootNode, overallRisk };
}

const MAX_NODE_DEPTH = 20;

function normalizeNode(item: Record<string, unknown>, depth = 0): AttackTreeNode | null {
  if (depth > MAX_NODE_DEPTH) return null;

  const id = typeof item["id"] === "string" ? item["id"].trim() : "";
  const description = typeof item["description"] === "string" ? item["description"].trim() : "";
  if (!id || !description) return null;

  const type = typeof item["type"] === "string" && ["AND", "OR", "LEAF"].includes(item["type"])
    ? (item["type"] as AttackTreeNode["type"])
    : "LEAF";

  const probability = normalizeUnitNumber(item["probability"]);
  const impact = typeof item["impact"] === "string" ? item["impact"].trim() : "unknown";
  const technique = typeof item["technique"] === "string" ? item["technique"].trim() || undefined : undefined;
  const relatedFindings = asStringArray(item["relatedFindings"]);
  const relatedThreats = asStringArray(item["relatedThreats"]);

  const children: AttackTreeNode[] = [];
  if (Array.isArray(item["children"])) {
    for (const child of item["children"]) {
      if (!isRecord(child)) continue;
      const node = normalizeNode(child, depth + 1);
      if (node) children.push(node);
    }
  }

  return { id, description, type, probability, impact, children, technique, relatedFindings, relatedThreats };
}

function treesToFindings(
  trees: AttackTree[],
  repoRoot: string,
  repoName: string,
): Finding[] {
  const findings: Finding[] = [];
  for (let i = 0; i < trees.length; i++) {
    const tree = trees[i];
    if (tree.overallRisk !== "critical" && tree.overallRisk !== "high") continue;

    const severity = tree.overallRisk === "critical" ? "ERROR" : "WARNING";
    const technique = tree.rootNode.technique;
    const goalSlug = tree.goal.slice(0, 40).replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-|-$/g, "").toLowerCase();
    const ruleId = technique ? `attack-tree/${technique}` : `attack-tree/${goalSlug || "chain"}`;
    const fingerprint = computeFingerprint(repoName, tree);

    const treeDescription = describeTree(tree.rootNode, 0);

    findings.push({
      scanner: "threat-model-pasta",
      fingerprint,
      ruleId,
      filePath: ".",
      startLine: i + 1,
      severity,
      message: `Attack tree: ${tree.goal} (risk: ${tree.overallRisk})`,
      evidence: treeDescription,
      scannerConfidence: tree.overallRisk === "critical" ? "HIGH" : "MEDIUM",
      subcategory: ["vuln"],
      likelihood: tree.overallRisk === "critical" ? "HIGH" : "MEDIUM",
      impact: "HIGH",
      cwe: [],
      score: scoreFindingMetadata({
        severity,
        likelihood: tree.overallRisk === "critical" ? "HIGH" : "MEDIUM",
        impact: "HIGH",
        subcategory: ["vuln"],
      }),
    });
  }

  return findings;
}

function describeTree(node: AttackTreeNode, depth: number): string {
  const indent = "  ".repeat(depth);
  const typeLabel = node.type === "LEAF" ? "" : ` [${node.type}]`;
  let line = `${indent}${node.id}: ${node.description}${typeLabel}`;
  if (node.technique) line += ` (ATT&CK: ${node.technique})`;

  const lines = [line];
  for (const child of node.children) {
    lines.push(describeTree(child, depth + 1));
  }

  return lines.join("\n");
}

function computeFingerprint(repoName: string, tree: AttackTree): string {
  const structureHash = hashTreeStructure(tree.rootNode);
  const source = [repoName, "threat-model-pasta", tree.overallRisk, structureHash].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function hashTreeStructure(node: AttackTreeNode): string {
  const parts: string[] = [node.type];
  if (node.technique) parts.push(node.technique);
  for (const ref of node.relatedFindings ?? []) parts.push(`f:${ref}`);
  for (const ref of node.relatedThreats ?? []) parts.push(`t:${ref}`);
  for (const child of node.children) parts.push(hashTreeStructure(child));
  return createHash("sha256").update(parts.join("|")).digest("hex").slice(0, 16);
}

function normalizeUnitNumber(value: unknown): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(1, numeric));
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((v) => String(v).trim()).filter(Boolean);
}

export const threatModelPastaTask: AgentTask<ScanOpts, { document: AttackSimulationDocument; findings: Finding[] }> = {
  id: "threat-model-pasta",
  displayName: "PASTA Attack Simulation",
  outputKind: "threat-model",
  dependsOn: ["threat-model-stride"],

  async run(_input, context): Promise<{ document: AttackSimulationDocument; findings: Finding[] }> {
    const cfg = resolveThreatModelConfig(context.config);
    const { strideThreats, upstreamFindings } = collectUpstreamContext(context);

    if (strideThreats.length === 0 && upstreamFindings.length === 0) {
      console.error("[threat-model-pasta] No upstream threats or findings to build attack trees from");
      return {
        document: { version: "1.0", trees: [], summary: { totalTrees: 0, criticalPaths: 0 } },
        findings: [],
      };
    }

    const prompt = buildPastaPrompt(strideThreats, upstreamFindings, cfg.maxTrees);
    const runtime = getAgentRuntime();

    let structuredOutput: unknown;
    let resultText = "";
    let costUsd = 0;

    const tag = "[threat-model-pasta]";
    console.error(`${tag} Starting PASTA analysis (model=${cfg.pastaModel})`);

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model: cfg.pastaModel,
          maxTurns: undefined,
          allowedTools: ["Read", "Glob", "Grep"],
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: PASTA_RESPONSE_SCHEMA,
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

    const parsed = structuredOutput ?? parseJson(resultText, tag);
    const trees = parsePastaResponse(parsed, cfg.maxTrees);
    const criticalPaths = trees.filter((t) => t.overallRisk === "critical" || t.overallRisk === "high").length;

    console.error(`${tag} Built ${trees.length} attack trees (${criticalPaths} critical/high)`);

    const document: AttackSimulationDocument = {
      version: "1.0",
      trees,
      summary: { totalTrees: trees.length, criticalPaths },
    };

    const findings = cfg.emitFindings
      ? treesToFindings(trees, context.repoRoot, context.repoName)
      : [];

    return attachTaskOutputMeta({ document, findings }, { costUsd });
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging a PASTA attack simulation finding in "${repoName}".`,
        "",
        `Rule: ${finding.ruleId}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Attack tree:\n${finding.evidence}` : "",
        "",
        "This finding represents a multi-step attack chain combining individual vulnerabilities.",
        "Verify the chain is realistic: each step must be exploitable and the chain must be achievable in sequence.",
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

export const __pastaInternals = {
  buildPastaPrompt,
  collectUpstreamContext,
  parsePastaResponse,
  normalizeTree,
  normalizeNode,
  treesToFindings,
  describeTree,
  computeFingerprint,
};

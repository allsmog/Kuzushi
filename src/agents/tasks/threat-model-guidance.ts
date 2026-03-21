import type { FileIndex } from "../../types.js";
import { isRecord } from "../../utils.js";
import { getTaskFileSpec, type PreReadResult } from "./pre-read.js";
import type { ThreatModelDocument, StrideThreat } from "./threat-modeling/types.js";

export type ThreatAwareDetectorTaskId =
  | "code-config-detect"
  | "ssrf-detect"
  | "nosql-injection-detect"
  | "prototype-pollution-detect"
  | "template-injection-detect"
  | "graphql-security-detect"
  | "race-condition-detect";

interface ThreatScore {
  threat: StrideThreat;
  score: number;
  reasons: string[];
}

interface DetectorThreatMetadata {
  cwes: Set<string>;
  keywords: string[];
}

const DETECTOR_THREAT_METADATA: Record<ThreatAwareDetectorTaskId, DetectorThreatMetadata> = {
  "code-config-detect": {
    cwes: new Set(),
    keywords: [],
  },
  "ssrf-detect": {
    cwes: new Set(["918"]),
    keywords: ["url", "fetch", "metadata", "internal service", "redirect"],
  },
  "nosql-injection-detect": {
    cwes: new Set(["943"]),
    keywords: ["mongo", "operator", "query", "document db"],
  },
  "prototype-pollution-detect": {
    cwes: new Set(["1321"]),
    keywords: ["prototype", "merge", "__proto__", "constructor"],
  },
  "template-injection-detect": {
    cwes: new Set(["1336"]),
    keywords: ["template", "render", "ssti"],
  },
  "graphql-security-detect": {
    cwes: new Set(),
    keywords: ["graphql", "resolver", "schema", "introspection", "authorization"],
  },
  "race-condition-detect": {
    cwes: new Set(["362"]),
    keywords: ["race", "concurrent", "lock", "toctou"],
  },
};

const GENERIC_THREAT_STOP_WORDS = new Set([
  "with",
  "from",
  "that",
  "this",
  "into",
  "user",
  "users",
  "request",
  "requests",
  "allows",
  "allow",
  "through",
  "missing",
  "without",
  "where",
  "when",
  "because",
  "using",
  "trusted",
  "client",
  "clients",
  "service",
  "services",
  "endpoint",
  "endpoints",
  "parameter",
  "parameters",
]);

export function buildThreatModelLeadsSection(
  taskId: ThreatAwareDetectorTaskId,
  strideOutput: unknown,
  fileIndex: FileIndex | undefined,
  preRead: PreReadResult | undefined,
): string {
  const parsed = asStrideTaskOutput(strideOutput);
  if (!parsed || parsed.document.threats.length === 0) {
    return "";
  }

  const shortlist = collectShortlistPaths(taskId, fileIndex, preRead);
  const shortlistCorpus = buildShortlistCorpus(taskId, fileIndex, preRead, shortlist);
  const scored = parsed.document.threats
    .map((threat) => scoreThreatForTask(taskId, threat, shortlist, shortlistCorpus))
    .filter((entry) => entry.score > 0)
    .sort((left, right) => {
      if (right.score !== left.score) {
        return right.score - left.score;
      }
      return compareImpact(right.threat.impact) - compareImpact(left.threat.impact);
    })
    .slice(0, 5);

  if (scored.length === 0) {
    return "";
  }

  const lines = ["## Threat model leads from STRIDE"];
  for (const entry of scored) {
    const cweSummary = entry.threat.relatedCwe.length > 0
      ? ` / ${entry.threat.relatedCwe.join(", ")}`
      : "";
    lines.push(
      `- [${entry.threat.id}] ${entry.threat.category} / ${entry.threat.impact}${cweSummary}: ${entry.threat.title}`,
    );
    lines.push(`  Why relevant: ${entry.reasons.join(", ")}`);
    const evidence = formatThreatEvidence(entry.threat);
    if (evidence) {
      lines.push(`  Evidence: ${evidence}`);
    }
  }
  lines.push("");
  return lines.join("\n");
}

function scoreThreatForTask(
  taskId: ThreatAwareDetectorTaskId,
  threat: StrideThreat,
  shortlist: Set<string>,
  shortlistCorpus: string,
): ThreatScore {
  const metadata = DETECTOR_THREAT_METADATA[taskId];
  const reasons: string[] = [];
  let score = 0;

  if (threatTouchesShortlist(threat, shortlist)) {
    score += 5;
    reasons.push("file overlap");
  }

  const cweOverlap = [...normalizeThreatCwes(threat.relatedCwe)].some((cwe) => metadata.cwes.has(cwe));
  if (cweOverlap) {
    score += 3;
    reasons.push(`CWE-${[...normalizeThreatCwes(threat.relatedCwe)].find((cwe) => metadata.cwes.has(cwe))}`);
  }

  if (matchesThreatKeywords(taskId, metadata, threat, shortlistCorpus)) {
    score += 2;
    reasons.push("keyword match");
  }

  if (threat.impact === "critical") {
    score += 1;
    reasons.push("critical impact");
  } else if (threat.impact === "high") {
    score += 0.5;
    reasons.push("high impact");
  }

  return { threat, score, reasons };
}

function matchesThreatKeywords(
  taskId: ThreatAwareDetectorTaskId,
  metadata: DetectorThreatMetadata,
  threat: StrideThreat,
  shortlistCorpus: string,
): boolean {
  const threatText = normalizeThreatText(threat);
  if (taskId === "code-config-detect") {
    return [...extractThreatKeywords(threatText)].some((keyword) => shortlistCorpus.includes(keyword));
  }

  return metadata.keywords.some((keyword) => threatText.includes(keyword.toLowerCase()));
}

function formatThreatEvidence(threat: StrideThreat): string {
  const anchors = (threat.evidenceAnchors ?? [])
    .slice(0, 2)
    .map((anchor) => `${anchor.filePath}:${anchor.startLine} (${anchor.description})`);
  if (anchors.length > 0) {
    return anchors.join("; ");
  }

  return threat.affectedFiles
    .slice(0, 2)
    .map((file) => `${file.filePath}:${file.startLine}`)
    .join("; ");
}

function collectShortlistPaths(
  taskId: ThreatAwareDetectorTaskId,
  fileIndex: FileIndex | undefined,
  preRead: PreReadResult | undefined,
): Set<string> {
  const shortlist = new Set<string>();

  for (const file of preRead?.files ?? []) {
    shortlist.add(normalizeComparablePath(file.path));
  }

  if (!fileIndex) {
    return shortlist;
  }

  const spec = getTaskFileSpec(taskId);
  if (!spec) {
    return shortlist;
  }

  for (const domain of spec.patternDomains ?? []) {
    for (const match of fileIndex.patternMatches[domain] ?? []) {
      shortlist.add(normalizeComparablePath(match.filePath));
    }
  }

  for (const entry of fileIndex.tree) {
    if (spec.namePatterns?.some((pattern) => pattern.test(entry.path))) {
      shortlist.add(normalizeComparablePath(entry.path));
      continue;
    }

    if (spec.pathFilter?.(entry.path)) {
      shortlist.add(normalizeComparablePath(entry.path));
    }
  }

  return shortlist;
}

function buildShortlistCorpus(
  taskId: ThreatAwareDetectorTaskId,
  fileIndex: FileIndex | undefined,
  preRead: PreReadResult | undefined,
  shortlist: Set<string>,
): string {
  const parts: string[] = [];

  for (const path of shortlist) {
    parts.push(path);
  }

  for (const file of preRead?.files ?? []) {
    parts.push(file.path.toLowerCase());
    parts.push(file.content.toLowerCase());
  }

  const spec = getTaskFileSpec(taskId);
  for (const domain of spec?.patternDomains ?? []) {
    for (const match of fileIndex?.patternMatches[domain] ?? []) {
      parts.push(match.lineContent.toLowerCase());
      parts.push(match.filePath.toLowerCase());
    }
  }

  return parts.join("\n");
}

function threatTouchesShortlist(threat: StrideThreat, shortlist: Set<string>): boolean {
  const threatFiles = collectThreatFiles(threat);
  for (const threatFile of threatFiles) {
    for (const shortlistPath of shortlist) {
      if (pathsOverlap(threatFile, shortlistPath)) {
        return true;
      }
    }
  }
  return false;
}

function collectThreatFiles(threat: StrideThreat): string[] {
  const files = new Set<string>();
  for (const file of threat.affectedFiles) {
    files.add(normalizeComparablePath(file.filePath));
  }
  for (const anchor of threat.evidenceAnchors ?? []) {
    files.add(normalizeComparablePath(anchor.filePath));
  }
  return [...files];
}

function normalizeThreatText(threat: StrideThreat): string {
  return [
    threat.title,
    threat.description,
    threat.attackVector,
    ...threat.preconditions,
    ...threat.existingMitigations,
    ...threat.missingMitigations,
  ]
    .join(" ")
    .toLowerCase();
}

function extractThreatKeywords(threatText: string): Set<string> {
  const keywords = new Set<string>();
  for (const token of threatText.split(/[^a-z0-9_]+/)) {
    const normalized = token.trim().toLowerCase();
    if (normalized.length < 4 || GENERIC_THREAT_STOP_WORDS.has(normalized)) {
      continue;
    }
    keywords.add(normalized);
    if (keywords.size >= 12) {
      break;
    }
  }
  return keywords;
}

function normalizeThreatCwes(values: string[]): Set<string> {
  const cwes = new Set<string>();
  for (const value of values) {
    const match = value.match(/(\d+)/);
    if (match) {
      cwes.add(match[1]);
    }
  }
  return cwes;
}

function compareImpact(impact: StrideThreat["impact"]): number {
  switch (impact) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    default:
      return 1;
  }
}

function normalizeComparablePath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\.\//, "").toLowerCase();
}

function pathsOverlap(left: string, right: string): boolean {
  return left === right || left.endsWith(`/${right}`) || right.endsWith(`/${left}`);
}

function asStrideTaskOutput(
  value: unknown,
): { document: ThreatModelDocument; findings: unknown[] } | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const document = value["document"];
  const findings = value["findings"];
  if (!isThreatModelDocument(document) || !Array.isArray(findings)) {
    return undefined;
  }

  return { document, findings };
}

function isThreatModelDocument(value: unknown): value is ThreatModelDocument {
  return isRecord(value)
    && Array.isArray(value["threats"])
    && isRecord(value["dfd"])
    && isRecord(value["summary"]);
}

export const __threatModelGuidanceInternals = {
  asStrideTaskOutput,
  buildShortlistCorpus,
  collectShortlistPaths,
  extractThreatKeywords,
  normalizeComparablePath,
  pathsOverlap,
  scoreThreatForTask,
};

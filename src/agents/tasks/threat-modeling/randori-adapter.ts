/**
 * Converts Randori PASTA plugin output (snake_case JSON) to Kuzushi's
 * ThreatModelDocument types.
 */
import { isRecord } from "../../../utils.js";
import type {
  DfdElement,
  EvidenceAnchor,
  StrideThreat,
  StrideCategory,
  ThreatModelDocument,
  TrustBoundary,
} from "./types.js";

const VALID_STRIDE_CATEGORIES = new Set<StrideCategory>([
  "spoofing", "tampering", "repudiation",
  "information-disclosure", "denial-of-service", "elevation-of-privilege",
]);
const VALID_IMPACTS = new Set(["critical", "high", "medium", "low"]);

// ── Public API ──

export function convertRandoriToThreatModel(randoriOutput: unknown): ThreatModelDocument | null {
  if (!isRecord(randoriOutput)) return null;

  const elements = parseDfdElements(randoriOutput["dfd"]);
  const trustBoundaries = parseTrustBoundaries(randoriOutput["dfd"]);
  const threats = parseThreatScenarios(randoriOutput["threat_scenarios"] ?? randoriOutput["threats"]);

  return {
    version: "1.0",
    dfd: { elements, trustBoundaries },
    threats,
    summary: buildSummary(threats),
  };
}

// ── DFD Elements ──

function parseDfdElements(dfd: unknown): DfdElement[] {
  if (!isRecord(dfd) || !Array.isArray(dfd["elements"])) return [];
  const out: DfdElement[] = [];
  for (const item of dfd["elements"]) {
    if (!isRecord(item)) continue;
    const id = str(item["id"]);
    const name = str(item["name"]);
    if (!id || !name) continue;

    out.push({
      id,
      type: normalizeElementType(str(item["type"])),
      name,
      description: str(item["description"]) || name,
      trustZone: str(item["trust_zone"]) || "unknown",
      source: optStr(item["source"]),
      target: optStr(item["target"]),
      protocol: optStr(item["protocol"]),
      dataClassification: optStr(item["data_classification"]),
    });
  }
  return out;
}

function normalizeElementType(t: string): DfdElement["type"] {
  const valid = new Set(["external-entity", "process", "data-store", "data-flow"]);
  return valid.has(t) ? (t as DfdElement["type"]) : "process";
}

// ── Trust Boundaries ──

function parseTrustBoundaries(dfd: unknown): TrustBoundary[] {
  if (!isRecord(dfd) || !Array.isArray(dfd["trust_boundaries"])) return [];
  const out: TrustBoundary[] = [];
  for (const item of dfd["trust_boundaries"]) {
    if (!isRecord(item)) continue;
    const id = str(item["id"]);
    const name = str(item["name"]);
    if (!id || !name) continue;

    out.push({
      id,
      name,
      innerZone: str(item["inner_zone"]) || "internal",
      outerZone: str(item["outer_zone"]) || "external",
      crossingFlows: strArray(item["crossing_flows"]),
    });
  }
  return out;
}

// ── Threat Scenarios ──

function parseThreatScenarios(scenarios: unknown): StrideThreat[] {
  if (!Array.isArray(scenarios)) return [];
  const out: StrideThreat[] = [];
  for (const item of scenarios) {
    if (!isRecord(item)) continue;
    const id = str(item["id"]);
    const title = str(item["title"]) || str(item["name"]);
    const category = normalizeStrideCategory(str(item["stride_category"]));
    if (!id || !title || !category) continue;

    const impact = normalizeImpact(str(item["impact"]));
    const probability = typeof item["probability"] === "number" ? item["probability"] : 0.5;
    const evidenceAnchors = parseEvidenceAnchors(item["evidence_anchors"]);

    // Handle both schema-ideal and actual Randori field names
    const elementId = strArray(item["target_assets"])[0]
      || strArray(item["affected_components"])[0]
      || "unknown";
    // mitre_attack can be a string or array of strings
    const mitre = item["mitre_attack"];
    const mitreStr = Array.isArray(mitre) ? mitre.map(String).join(", ") : str(mitre);
    const attackVector = str(item["attack_technique_id"])
      || mitreStr
      || str(item["attack_scenario"])
      || "unknown";

    out.push({
      id,
      elementId,
      category,
      title,
      description: str(item["description"]) || title,
      attackVector,
      preconditions: strArray(item["gaps"]),
      impact,
      likelihood: probabilityToLikelihood(probability),
      existingMitigations: strArray(item["existing_controls"]),
      missingMitigations: strArray(item["recommended_mitigations"])
        || (str(item["recommended_remediation"]) ? [str(item["recommended_remediation"])] : []),
      relatedCwe: buildCweList(item),
      affectedFiles: evidenceAnchors.map((a) => ({ filePath: a.filePath, startLine: a.startLine })),
      ...(evidenceAnchors.length > 0 ? { evidenceAnchors } : {}),
    });
  }
  return out;
}

function normalizeStrideCategory(value: string): StrideCategory | null {
  // Handle both hyphenated and underscored variants
  const normalized = value.replace(/_/g, "-");
  return VALID_STRIDE_CATEGORIES.has(normalized as StrideCategory) ? (normalized as StrideCategory) : null;
}

function normalizeImpact(value: string): StrideThreat["impact"] {
  return VALID_IMPACTS.has(value) ? (value as StrideThreat["impact"]) : "medium";
}

function probabilityToLikelihood(p: number): StrideThreat["likelihood"] {
  if (p >= 0.7) return "high";
  if (p >= 0.4) return "medium";
  return "low";
}

function parseEvidenceAnchors(value: unknown): EvidenceAnchor[] {
  if (!Array.isArray(value)) return [];
  const out: EvidenceAnchor[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const filePath = str(item["file_path"]);
    const description = str(item["description"]);
    if (!filePath || !description) continue;
    out.push({
      filePath,
      startLine: Math.max(1, Math.floor(Number(item["start_line"]) || 1)),
      description,
    });
  }
  return out;
}

function buildCweList(item: Record<string, unknown>): string[] {
  const cwes: string[] = [];
  // Handle both schema-ideal and actual field names
  const owasp = str(item["owasp_category"]) || str(item["owasp"]);
  if (owasp) {
    // Extract just the code (e.g., "A02:2021 – Cryptographic Failures" → "A02")
    const match = owasp.match(/A\d{2}/);
    cwes.push(`OWASP-${match ? match[0] : owasp}`);
  }
  const capec = str(item["capec_id"]);
  if (capec) cwes.push(capec);
  // mitre_attack can be a string or array of strings like ["T1059 - Command...", "T1190 - Exploit..."]
  const mitre = item["mitre_attack"] ?? item["attack_technique_id"];
  const mitreEntries = Array.isArray(mitre) ? mitre.map(String) : [str(mitre)];
  for (const entry of mitreEntries) {
    const tMatch = entry.match(/T\d{4}/);
    if (tMatch) cwes.push(`ATT&CK-${tMatch[0]}`);
  }
  return cwes;
}

// ── Summary ──

function buildSummary(threats: StrideThreat[]): ThreatModelDocument["summary"] {
  const bySeverity: Record<string, number> = {};
  const byCategory = {} as Record<StrideCategory, number>;
  for (const t of threats) {
    bySeverity[t.impact] = (bySeverity[t.impact] || 0) + 1;
    byCategory[t.category] = (byCategory[t.category] || 0) + 1;
  }
  return { total: threats.length, bySeverity, byCategory };
}

// ── Helpers ──

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function optStr(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const trimmed = v.trim();
  return trimmed || undefined;
}

function strArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.map((x) => String(x).trim()).filter(Boolean);
}

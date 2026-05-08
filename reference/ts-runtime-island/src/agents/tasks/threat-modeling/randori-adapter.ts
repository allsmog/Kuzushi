/**
 * Converts Randori PASTA plugin output (snake_case JSON) to Kuzushi's
 * ThreatModelDocument types.
 */
import { isRecord } from "../../../utils.js";
import type {
  DfdFlow,
  DfdNode,
  EvidenceAnchor,
  StrideCategory,
  StrideThreat,
  ThreatModelAttackerStory,
  ThreatModelCriticalityBuckets,
  ThreatModelDocument,
  ThreatModelInputCategories,
  ThreatModelNarrative,
  ThreatModelProvenance,
  ThreatModelReference,
  TrustBoundary,
} from "./types.js";

const VALID_STRIDE_CATEGORIES = new Set<StrideCategory>([
  "spoofing",
  "tampering",
  "repudiation",
  "information-disclosure",
  "denial-of-service",
  "elevation-of-privilege",
]);
const VALID_IMPACTS = new Set(["critical", "high", "medium", "low"]);

// ── Public API ──

export function convertRandoriToThreatModel(randoriOutput: unknown): ThreatModelDocument | null {
  if (!isRecord(randoriOutput)) return null;

  const nodes = parseDfdNodes(randoriOutput["dfd"]);
  const flows = parseDfdFlows(randoriOutput["dfd"]);
  const trustBoundaries = parseTrustBoundaries(randoriOutput["dfd"]);
  const threats = repairThreatActorIds(
    parseThreatScenarios(randoriOutput["threat_scenarios"] ?? randoriOutput["threats"]),
    nodes,
  );
  const narrative = parseNarrative(randoriOutput["narrative"]);
  const provenance = parseProvenance(randoriOutput["provenance"]);

  return {
    version: "2.0",
    dfd: {
      nodes,
      flows,
      trustBoundaries: trustBoundaries.map((boundary) => ({
        ...boundary,
        crossingFlowIds: boundary.crossingFlowIds.filter((flowId) =>
          flows.some((flow) => flow.id === flowId),
        ),
      })),
    },
    threats,
    summary: buildSummary(threats),
    ...(narrative ? { narrative } : {}),
    ...(provenance ? { provenance } : {}),
  };
}

// ── Narrative (S5 synthesis) ──

function parseNarrative(raw: unknown): ThreatModelNarrative | null {
  if (!isRecord(raw)) return null;
  const overview = str(raw["overview"]);
  const inputCategories = parseInputCategories(raw["input_categories"] ?? raw["inputCategories"]);
  const attackerStories = parseAttackerStories(raw["attacker_stories"] ?? raw["attackerStories"]);
  const criticalityBuckets = parseCriticalityBuckets(
    raw["criticality_buckets"] ?? raw["criticalityBuckets"],
  );
  const outOfScope = strArray(raw["out_of_scope"] ?? raw["outOfScope"]);

  // Require at least one populated section — otherwise fall back to no narrative
  // so renderers can keep using the DFD/STRIDE view.
  const hasContent =
    overview.length > 0 ||
    attackerStories.length > 0 ||
    outOfScope.length > 0 ||
    Object.values(inputCategories).some((v) => v.length > 0) ||
    Object.values(criticalityBuckets).some((v) => v.length > 0);
  if (!hasContent) return null;

  return {
    overview,
    inputCategories,
    attackerStories,
    criticalityBuckets,
    outOfScope,
  };
}

function parseInputCategories(raw: unknown): ThreatModelInputCategories {
  const empty: ThreatModelInputCategories = {
    attackerControlled: [],
    operatorControlled: [],
    developerControlled: [],
    externalServices: [],
    sandboxBoundary: [],
    assumptions: [],
  };
  if (!isRecord(raw)) return empty;
  return {
    attackerControlled: strArray(raw["attacker_controlled"] ?? raw["attackerControlled"]),
    operatorControlled: strArray(raw["operator_controlled"] ?? raw["operatorControlled"]),
    developerControlled: strArray(raw["developer_controlled"] ?? raw["developerControlled"]),
    externalServices: strArray(raw["external_services"] ?? raw["externalServices"]),
    sandboxBoundary: strArray(raw["sandbox_boundary"] ?? raw["sandboxBoundary"]),
    assumptions: strArray(raw["assumptions"]),
  };
}

function parseAttackerStories(raw: unknown): ThreatModelAttackerStory[] {
  if (!Array.isArray(raw)) return [];
  const out: ThreatModelAttackerStory[] = [];
  for (const item of raw) {
    if (!isRecord(item)) continue;
    const title = str(item["title"]);
    const narrative = str(item["narrative"]);
    const mitigation = str(item["mitigation"]);
    if (!title || !narrative) continue;
    const threatIds = strArray(item["threat_ids"] ?? item["threatIds"]);
    out.push({
      title,
      narrative,
      mitigation,
      ...(threatIds.length > 0 ? { threatIds } : {}),
    });
  }
  return out;
}

function parseCriticalityBuckets(raw: unknown): ThreatModelCriticalityBuckets {
  const empty: ThreatModelCriticalityBuckets = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };
  if (!isRecord(raw)) return empty;
  return {
    critical: strArray(raw["critical"]),
    high: strArray(raw["high"]),
    medium: strArray(raw["medium"]),
    low: strArray(raw["low"]),
  };
}

// ── DFD Graph v2 ──

function parseDfdNodes(dfd: unknown): DfdNode[] {
  if (!isRecord(dfd)) return [];
  const rawNodes = Array.isArray(dfd["nodes"]) ? dfd["nodes"] : dfd["elements"];
  if (!Array.isArray(rawNodes)) return [];
  const out: DfdNode[] = [];
  for (const item of rawNodes) {
    if (!isRecord(item)) continue;
    const id = str(item["id"]);
    const name = str(item["name"]);
    if (!id || !name) continue;
    const type = normalizeNodeType(str(item["type"]));
    if (!type) continue;

    out.push({
      id,
      type,
      name,
      description: str(item["description"]) || name,
      trustZone: str(item["trust_zone"]) || "unknown",
      ...optionalEvidenceAndProvenance(item),
    });
  }
  return out;
}

function parseDfdFlows(dfd: unknown): DfdFlow[] {
  if (!isRecord(dfd)) return [];
  const rawFlows = Array.isArray(dfd["flows"]) ? dfd["flows"] : [];
  const rawElements = Array.isArray(dfd["elements"]) ? dfd["elements"] : [];
  const out: DfdFlow[] = [];
  for (const item of [...rawFlows, ...rawElements]) {
    if (!isRecord(item)) continue;
    const type = str(item["type"]).toLowerCase().replace(/_/g, "-");
    const sourceId = str(item["source_id"] ?? item["sourceId"] ?? item["source"]);
    const targetId = str(item["target_id"] ?? item["targetId"] ?? item["target"]);
    if (rawFlows.length === 0 && type !== "data-flow" && (!sourceId || !targetId)) continue;
    const id = str(item["id"]);
    if (!id || !sourceId || !targetId) continue;
    out.push({
      id,
      name: optStr(item["name"]),
      description: str(item["description"]) || str(item["name"]) || `${sourceId} -> ${targetId}`,
      sourceId,
      targetId,
      protocol: optStr(item["protocol"]),
      dataClassification: optStr(item["data_classification"] ?? item["dataClassification"]),
      trustBoundaryIds: strArray(item["trust_boundary_ids"] ?? item["trustBoundaryIds"]),
      ...optionalEvidenceAndProvenance(item),
    });
  }
  return dedupeById(out);
}

function normalizeNodeType(t: string): DfdNode["type"] | null {
  // Map common agent output variants to canonical types
  switch (t.toLowerCase()) {
    case "external-entity":
    case "external":
    case "external_entity":
      return "external-entity";
    case "data-store":
    case "datastore":
    case "data_store":
      return "data-store";
    case "data-flow":
    case "dataflow":
    case "data_flow":
      return null;
    case "process":
      return "process";
    default:
      return "process";
  }
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
      crossingFlowIds: strArray(
        item["crossing_flow_ids"] ?? item["crossingFlowIds"] ?? item["crossing_flows"],
      ),
      ...optionalEvidenceAndProvenance(item),
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
    const actorIds = strArray(item["actor_ids"] ?? item["actorIds"] ?? item["actors"]);
    const entrypointIds = strArray(
      item["entrypoint_ids"] ?? item["entrypointIds"] ?? item["entry_points"],
    );
    const flowIds = strArray(item["flow_ids"] ?? item["flowIds"] ?? item["flows"]);

    // Handle both schema-ideal and actual Randori field names
    const targetElementIds = uniqueStrings([
      ...strArray(item["target_element_ids"] ?? item["targetElementIds"]),
      ...strArray(item["target_assets"]),
      ...strArray(item["affected_components"]),
    ]);
    const elementId = targetElementIds[0] ?? "unknown";
    // mitre_attack can be a string or array of strings
    const mitre = item["mitre_attack"];
    const mitreStr = Array.isArray(mitre) ? mitre.map(String).join(", ") : str(mitre);
    const attackVector =
      str(item["attack_technique_id"]) || mitreStr || str(item["attack_scenario"]) || "unknown";
    const confidence = normalizeConfidence(item["confidence"]);
    const provenance = parseProvenance(item["provenance"]);

    out.push({
      id,
      targetElementIds: targetElementIds.length > 0 ? targetElementIds : [elementId],
      ...(actorIds.length > 0 ? { actorIds } : {}),
      ...(entrypointIds.length > 0 ? { entrypointIds } : {}),
      ...(flowIds.length > 0 ? { flowIds } : {}),
      category,
      title,
      description: str(item["description"]) || title,
      attackVector,
      preconditions: strArray(item["gaps"]),
      impact,
      likelihood: probabilityToLikelihood(probability),
      probability,
      ...(confidence ? { confidence } : {}),
      existingMitigations: strArray(item["existing_controls"]),
      missingMitigations: recommendedMitigations(item),
      relatedCwe: buildCweList(item),
      affectedFiles: evidenceAnchors.map((a) => ({ filePath: a.filePath, startLine: a.startLine })),
      ...(evidenceAnchors.length > 0 ? { evidenceAnchors } : {}),
      sources: parseReferences(item["sources"], "source"),
      sinks: parseReferences(item["sinks"], "sink"),
      guards: parseReferences(item["guards"], "guard"),
      sanitizers: parseReferences(item["sanitizers"], "sanitizer"),
      requiredCapabilities: strArray(item["required_capabilities"] ?? item["requiredCapabilities"]),
      ...(provenance ? { provenance } : {}),
      elementId,
    });
  }
  return out;
}

function repairThreatActorIds(threats: StrideThreat[], nodes: DfdNode[]): StrideThreat[] {
  const nodeIds = new Set(nodes.map((node) => node.id));
  const externalNodes = nodes.filter((node) => node.type === "external-entity");
  return threats.map((threat) => {
    if (!threat.actorIds?.length) return threat;
    const actorIds = uniqueStrings(
      threat.actorIds.map((id) => repairActorId(id, nodeIds, externalNodes)),
    );
    return { ...threat, actorIds };
  });
}

function repairActorId(id: string, nodeIds: ReadonlySet<string>, externalNodes: DfdNode[]): string {
  if (nodeIds.has(id)) return id;
  const normalized = id.toLowerCase();
  if (normalized.includes("ext")) return externalNodes[0]?.id ?? id;
  if (normalized.includes("dev") || normalized.includes("int")) {
    return externalNodes[1]?.id ?? externalNodes[0]?.id ?? id;
  }
  return id;
}

function normalizeStrideCategory(value: string): StrideCategory | null {
  // Handle both hyphenated and underscored variants
  const normalized = value.replace(/_/g, "-");
  return VALID_STRIDE_CATEGORIES.has(normalized as StrideCategory)
    ? (normalized as StrideCategory)
    : null;
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
      ...(Number.isFinite(Number(item["end_line"]))
        ? { endLine: Math.max(1, Math.floor(Number(item["end_line"]))) }
        : {}),
      ...(str(item["symbol"]) ? { symbol: str(item["symbol"]) } : {}),
      description,
      ...(str(item["snippet"]) ? { snippet: str(item["snippet"]) } : {}),
      ...(str(item["source"]) ? { source: str(item["source"]) } : {}),
      ...optionalProvenance(item),
    });
  }
  return out;
}

function parseReferences(
  value: unknown,
  fallbackKind: ThreatModelReference["kind"],
): ThreatModelReference[] {
  if (!Array.isArray(value)) return [];
  const out: ThreatModelReference[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const ref: ThreatModelReference = {
      kind: str(item["kind"]) || fallbackKind,
      ...(str(item["name"]) ? { name: str(item["name"]) } : {}),
      ...(str(item["element_id"] ?? item["elementId"])
        ? { elementId: str(item["element_id"] ?? item["elementId"]) }
        : {}),
      ...(str(item["file_path"] ?? item["filePath"])
        ? { filePath: str(item["file_path"] ?? item["filePath"]) }
        : {}),
      ...(Number.isFinite(Number(item["start_line"] ?? item["startLine"]))
        ? { startLine: Math.max(1, Math.floor(Number(item["start_line"] ?? item["startLine"]))) }
        : {}),
      ...(Number.isFinite(Number(item["end_line"] ?? item["endLine"]))
        ? { endLine: Math.max(1, Math.floor(Number(item["end_line"] ?? item["endLine"]))) }
        : {}),
      ...(str(item["symbol"]) ? { symbol: str(item["symbol"]) } : {}),
      ...(str(item["description"]) ? { description: str(item["description"]) } : {}),
      ...(str(item["snippet"]) ? { snippet: str(item["snippet"]) } : {}),
      ...(str(item["source"]) ? { source: str(item["source"]) } : {}),
      ...optionalProvenance(item),
    };
    if (ref.name || ref.elementId || ref.filePath || ref.description) out.push(ref);
  }
  return out;
}

function recommendedMitigations(item: Record<string, unknown>): string[] {
  const recommended = strArray(item["recommended_mitigations"]);
  if (recommended.length > 0) return recommended;
  const remediation = str(item["recommended_remediation"]);
  return remediation ? [remediation] : [];
}

function normalizeConfidence(value: unknown): StrideThreat["confidence"] | undefined {
  const raw = str(value).toLowerCase();
  if (raw === "high" || raw === "medium" || raw === "low") return raw;
  return undefined;
}

function parseProvenance(value: unknown): ThreatModelProvenance | null {
  if (!isRecord(value)) return null;
  const source = str(value["source"]);
  const generatedAt = str(value["generated_at"] ?? value["generatedAt"]);
  const model = str(value["model"]);
  const notes = strArray(value["notes"]);
  const fallback = typeof value["fallback"] === "boolean" ? value["fallback"] : undefined;
  const out: ThreatModelProvenance = {
    ...(source ? { source } : {}),
    ...(generatedAt ? { generatedAt } : {}),
    ...(model ? { model } : {}),
    ...(fallback !== undefined ? { fallback } : {}),
    ...(notes.length > 0 ? { notes } : {}),
  };
  return Object.keys(out).length > 0 ? out : null;
}

function optionalProvenance(item: Record<string, unknown>): { provenance?: ThreatModelProvenance } {
  const provenance = parseProvenance(item["provenance"]);
  return provenance ? { provenance } : {};
}

function optionalEvidenceAndProvenance(item: Record<string, unknown>): {
  evidenceAnchors?: EvidenceAnchor[];
  provenance?: ThreatModelProvenance;
} {
  const evidenceAnchors = parseEvidenceAnchors(item["evidence_anchors"] ?? item["evidenceAnchors"]);
  return {
    ...(evidenceAnchors.length > 0 ? { evidenceAnchors } : {}),
    ...optionalProvenance(item),
  };
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
  if (typeof v === "string" && v.trim()) return [v.trim()];
  if (!Array.isArray(v)) return [];
  return v.map((x) => String(x).trim()).filter(Boolean);
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function dedupeById<T extends { id: string }>(items: T[]): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const item of items) {
    if (seen.has(item.id)) continue;
    seen.add(item.id);
    out.push(item);
  }
  return out;
}

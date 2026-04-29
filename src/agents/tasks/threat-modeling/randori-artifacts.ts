/**
 * Reads Randori PASTA plugin output artifacts from randori-output/.
 * The plugin writes JSON stage files during execution; we read them after completion.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

export interface RandoriArtifacts {
  state: Record<string, unknown> | null;
  s1Objectives: Record<string, unknown> | null;
  s2Scope: Record<string, unknown> | null;
  s3Decomposition: Record<string, unknown> | null;
  s4Threats: Record<string, unknown> | null;
  /** Narrative synthesis (S5) — Overview / InputCategories / AttackerStories / Criticality / OutOfScope. */
  narrative: Record<string, unknown> | null;
}

export function readRandoriArtifacts(
  repoRoot: string,
  relativeOutputDir?: string,
): RandoriArtifacts {
  const outputDir = path.join(repoRoot, relativeOutputDir ?? "randori-output");
  return {
    state: readJson(path.join(outputDir, "randori-state.json")),
    s1Objectives: readJson(path.join(outputDir, "pasta-s1.json")),
    s2Scope: readJson(path.join(outputDir, "pasta-s2.json")),
    s3Decomposition: readJson(path.join(outputDir, "pasta-s3.json")),
    s4Threats: readJson(path.join(outputDir, "pasta-s4.json")),
    narrative: readJson(path.join(outputDir, "pasta-narrative.json")),
  };
}

/**
 * Build a consolidated Randori output object that convertRandoriToThreatModel() expects.
 * Merges S2 (actors/services → DFD elements), S3 (trust boundaries, entry points), and S4 (threats).
 *
 * Randori's actual output structure:
 * - S2: { actors[], services[], data_flows[], databases[] }
 * - S3: { trust_boundaries[], entry_points[], dfd_diagram: "dfd.mmd" }  (no dfd.elements!)
 * - S4: { threats[] }  (not threat_scenarios!)
 */
export interface MergeRandoriStageOptions {
  fallbackMaxThreats?: number;
  synthesizeThreats?: boolean;
}

export function mergeRandoriStageOutputs(
  artifacts: RandoriArtifacts,
  options: MergeRandoriStageOptions = {},
): Record<string, unknown> | null {
  // Build the DFD from S2+S3 regardless of whether S4 exists.
  // Previously this returned null when S4 was missing, which discarded
  // the entire DFD and left carlini-threat-hunt with no external entities.
  const s2 = artifacts.s2Scope;
  const s3 = artifacts.s3Decomposition;
  const s4 = artifacts.s4Threats;

  if (!s2 && !s3 && !s4) return null;

  const merged: Record<string, unknown> = s4 ? { ...s4 } : {};

  // S4 uses "threats" not "threat_scenarios" — normalize
  if (merged["threats"] && !merged["threat_scenarios"]) {
    merged["threat_scenarios"] = merged["threats"];
  }
  const existingThreats = merged["threat_scenarios"] ?? merged["threats"];
  const hasThreats = Array.isArray(existingThreats) && existingThreats.length > 0;
  if (!hasThreats && options.fallbackMaxThreats && options.synthesizeThreats !== false) {
    const fallbackThreats = buildFallbackS4Threats(artifacts, options.fallbackMaxThreats);
    if (fallbackThreats.length > 0) {
      merged["threat_scenarios"] = fallbackThreats;
      merged["threats"] = fallbackThreats;
      merged["fallback_generated"] = true;
      merged["fallback_reason"] = "s4-missing-or-empty";
    }
  }
  // Ensure threats array exists even without S4 so downstream gets a valid document.
  if (!merged["threat_scenarios"] && !merged["threats"]) {
    merged["threat_scenarios"] = [];
    merged["threats"] = [];
  }

  // Build DFD from S2 actors/services + S3 dfd_elements + S3 trust boundaries
  const dfd: Record<string, unknown> = {};
  const seenIds = new Set<string>();
  const seenFlowIds = new Set<string>();
  const elements: Array<Record<string, unknown>> = [];
  const flows: Array<Record<string, unknown>> = [];

  // Synthesize DFD elements from S2 actors and services
  if (s2) {
    // Actors → external entities or processes
    for (const actor of asArray(s2["actors"])) {
      const id = str(actor["id"]);
      if (!id || seenIds.has(id)) continue;
      seenIds.add(id);
      const type = actorTypeToDfdType(str(actor["type"]));
      elements.push({
        id,
        type,
        name: str(actor["name"]),
        description: str(actor["description"]),
        trust_zone: str(actor["trust_level"]) || "external",
      });
    }
    // Services → processes
    for (const svc of asArray(s2["services"])) {
      const id = str(svc["id"]);
      if (!id || seenIds.has(id)) continue;
      seenIds.add(id);
      elements.push({
        id,
        type: "process",
        name: str(svc["name"]),
        description: str(svc["description"]),
        trust_zone: "internal",
      });
    }
    // Databases → data stores
    for (const db of asArray(s2["databases"])) {
      const id = str(db["id"]);
      if (!id || seenIds.has(id)) continue;
      seenIds.add(id);
      elements.push({
        id,
        type: "data-store",
        name: str(db["name"]),
        description: str(db["description"]),
        trust_zone: "internal",
      });
    }
    // Data flows
    for (const flow of asArray(s2["data_flows"])) {
      const id = str(flow["id"]);
      if (!id || seenFlowIds.has(id)) continue;
      const source = str(flow["source"] ?? flow["from"]);
      const target = str(flow["destination"] ?? flow["target"] ?? flow["to"]);
      if (!source || !target) continue;
      seenFlowIds.add(id);
      const name = str(flow["data"]) || str(flow["label"]) || `${source} → ${target}`;
      const flowRecord = {
        id,
        name,
        description: str(flow["description"]) || name,
        source_id: source,
        target_id: target,
        protocol: str(flow["protocol"]),
        data_classification: str(flow["sensitivity"] ?? flow["classification"]),
        trust_boundary_ids: strArray(flow["crosses"] ?? flow["trust_boundary_ids"]),
      };
      flows.push(flowRecord);
      elements.push({
        ...flowRecord,
        id,
        type: "data-flow",
        trust_zone: "cross-boundary",
        source,
        target,
      });
    }
    // Component collections emitted by newer target-brief prompts:
    // { components: { workflows: [...], actions: [...], scripts: [...] } }
    const components = s2["components"];
    if (isRecord(components)) {
      for (const [kind, list] of Object.entries(components)) {
        for (const component of asArray(list)) {
          const id = str(component["id"]) || str(component["name"]);
          if (!id || seenIds.has(id)) continue;
          seenIds.add(id);
          elements.push({
            id,
            type: componentKindToDfdType(kind),
            name: str(component["name"]) || id,
            description: str(component["description"]) || kind,
            trust_zone: str(component["trust_zone"]) || str(component["trustZone"]) || "internal",
          });
        }
      }
    }
  }

  // Incorporate S3's own dfd_elements (the agent often writes richer elements
  // directly in S3 that aren't present in S2's actor/service breakdown).
  if (s3) {
    for (const elem of asArray(s3["external_entities"])) {
      const id = str(elem["id"]);
      if (!id || seenIds.has(id)) continue;
      seenIds.add(id);
      elements.push({
        id,
        type: "external-entity",
        name: str(elem["name"]) || id,
        description: str(elem["description"]) || str(elem["notes"]) || str(elem["name"]) || id,
        trust_zone: str(elem["trust_zone"]) || "external",
      });
    }

    for (const elem of asArray(s3["entry_points"])) {
      const id = str(elem["id"]);
      if (!id || seenIds.has(id)) continue;
      seenIds.add(id);
      elements.push({
        id,
        type: "process",
        name: str(elem["name"]) || id,
        description: str(elem["description"]) || str(elem["notes"]) || str(elem["name"]) || id,
        trust_zone: str(elem["trust_zone"]) || "entrypoint",
      });
    }

    for (const elem of asArray(s3["processes"])) {
      const id = str(elem["id"]);
      if (!id || seenIds.has(id)) continue;
      seenIds.add(id);
      elements.push({
        id,
        type: "process",
        name: str(elem["name"]) || id,
        description: str(elem["description"]) || str(elem["notes"]) || str(elem["name"]) || id,
        trust_zone: str(elem["trust_zone"]) || "internal",
      });
    }

    for (const elem of asArray(s3["data_stores"])) {
      const id = str(elem["id"]);
      if (!id || seenIds.has(id)) continue;
      seenIds.add(id);
      elements.push({
        id,
        type: "data-store",
        name: str(elem["name"]) || id,
        description: str(elem["description"]) || str(elem["notes"]) || str(elem["name"]) || id,
        trust_zone: str(elem["trust_zone"]) || "internal",
      });
    }

    for (const elem of asArrayOrRecordCollections(s3["dfd_elements"])) {
      const id = str(elem["id"]);
      if (!id || seenIds.has(id)) continue;
      seenIds.add(id);
      elements.push({
        id,
        type: normalizeDfdType(str(elem["type"])),
        name: str(elem["name"]),
        description: str(elem["description"]),
        trust_zone: str(elem["trust_zone"]) || str(elem["component"]) || "unknown",
      });
    }

    for (const flow of asArray(s3["data_flows"])) {
      const id = str(flow["id"]);
      if (!id || seenFlowIds.has(id)) continue;
      const source = str(flow["source_id"] ?? flow["source"] ?? flow["from"]);
      const target = str(flow["target_id"] ?? flow["target"] ?? flow["to"]);
      if (!source || !target) continue;
      seenFlowIds.add(id);
      const name =
        str(flow["name"]) || str(flow["label"]) || str(flow["data"]) || `${source} → ${target}`;
      const trustBoundaryIds = strArray(flow["trust_boundary_ids"] ?? flow["crosses"]);
      const flowRecord = {
        id,
        name,
        description: str(flow["description"]) || name,
        source_id: source,
        target_id: target,
        protocol: str(flow["protocol"]),
        data_classification: str(flow["data_classification"] ?? flow["classification"]),
        trust_boundary_ids: trustBoundaryIds,
      };
      flows.push(flowRecord);
      elements.push({
        ...flowRecord,
        id,
        type: "data-flow",
        trust_zone: trustBoundaryIds.length > 0 ? trustBoundaryIds.join(",") : "cross-boundary",
        source,
        target,
      });
    }

    // Trust boundaries from S3
    const boundaries: Array<Record<string, unknown>> = [];
    for (const tb of asArray(s3["trust_boundaries"])) {
      const id = str(tb["id"]);
      const explicitCrossings = strArray(
        tb["crossing_flow_ids"] ?? tb["crossing_flows"] ?? tb["flows"],
      );
      const inferredCrossings = flows
        .filter((flow) => strArray(flow["trust_boundary_ids"]).includes(id))
        .map((flow) => str(flow["id"]));
      boundaries.push({
        id,
        name: str(tb["name"]),
        inner_zone: str(tb["name"]),
        outer_zone: "external",
        crossing_flow_ids: uniqueStrings([...explicitCrossings, ...inferredCrossings]),
      });
    }
    dfd["trust_boundaries"] = boundaries;
  }

  dfd["elements"] = elements;
  dfd["nodes"] = elements.filter(
    (element) => normalizeDfdType(str(element["type"])) !== "data-flow",
  );
  dfd["flows"] = flows;
  merged["dfd"] = dfd;

  // Narrative synthesis (S5) — pass through so the adapter can attach it to
  // ThreatModelDocument.narrative. Snake_case keys are normalised by the adapter.
  if (artifacts.narrative) {
    merged["narrative"] = artifacts.narrative;
  }

  return merged;
}

export function ensureFallbackS4Artifact(
  repoRoot: string,
  relativeOutputDir: string,
  artifacts: RandoriArtifacts,
  maxThreats = 20,
): { written: boolean; path: string; threats: Array<Record<string, unknown>> } {
  const outputDir = path.join(repoRoot, relativeOutputDir);
  const filePath = path.join(outputDir, "pasta-s4.json");
  const existing = artifacts.s4Threats;
  const existingThreats = existing?.["threat_scenarios"] ?? existing?.["threats"];
  if (Array.isArray(existingThreats) && existingThreats.length > 0) {
    return {
      written: false,
      path: filePath,
      threats: existingThreats as Array<Record<string, unknown>>,
    };
  }

  const threats = buildFallbackS4Threats(artifacts, maxThreats);
  if (threats.length === 0) return { written: false, path: filePath, threats };

  mkdirSync(outputDir, { recursive: true });
  writeFileSync(
    filePath,
    `${JSON.stringify(
      {
        stage: "S4",
        generated_by: "kuzushi-fallback",
        fallback_reason: "s4-missing-or-empty",
        threats,
        threat_scenarios: threats,
      },
      null,
      2,
    )}\n`,
    "utf-8",
  );
  return { written: true, path: filePath, threats };
}

export function buildFallbackS4Threats(
  artifacts: RandoriArtifacts,
  maxThreats = 20,
): Array<Record<string, unknown>> {
  const candidates = collectFallbackCandidates(artifacts);
  return candidates.slice(0, Math.max(1, maxThreats)).map((candidate, index) => {
    const text = [
      candidate.name,
      candidate.description,
      ...candidate.gaps,
      ...candidate.grounding,
    ].join(" ");
    const stride = inferStrideCategory(text);
    const impact = inferImpact(candidate);
    const evidenceAnchors = parseEvidenceAnchors(candidate);
    const target = candidate.id || candidate.name || `fallback-${index + 1}`;

    return {
      id: `S4-FB-${String(index + 1).padStart(3, "0")}`,
      title: `${candidate.kind}: ${candidate.name || target}`,
      description:
        candidate.description ||
        `Fallback threat derived from ${candidate.kind.toLowerCase()} evidence in S3/S2 artifacts.`,
      stride_category: stride,
      target_assets: [target],
      affected_components: [target],
      probability: inferProbability(candidate),
      impact,
      attack_scenario:
        candidate.description ||
        `Attack crosses ${candidate.name || candidate.kind} without an LLM-authored S4 scenario.`,
      gaps: candidate.gaps,
      existing_controls: candidate.controls,
      recommended_mitigations: recommendedMitigations(stride),
      mitre_attack: mitreForStride(stride),
      owasp_category: owaspForStride(stride),
      evidence_anchors: evidenceAnchors,
    };
  });
}

interface FallbackCandidate {
  kind: string;
  id: string;
  name: string;
  description: string;
  riskLevel: string;
  gaps: string[];
  controls: string[];
  grounding: string[];
  filePath: string;
}

function collectFallbackCandidates(artifacts: RandoriArtifacts): FallbackCandidate[] {
  const candidates: FallbackCandidate[] = [];
  const s3 = artifacts.s3Decomposition;
  if (s3) {
    for (const tb of asArray(s3["trust_boundaries"])) {
      candidates.push(candidateFromRecord("Boundary abuse", tb));
    }
    for (const entry of asArray(s3["entry_points"])) {
      candidates.push(candidateFromRecord("Entrypoint abuse", entry));
    }
  }

  if (candidates.length > 0) return candidates;

  const s2 = artifacts.s2Scope;
  if (!s2) return candidates;
  for (const actor of asArray(s2["actors"])) {
    candidates.push(candidateFromRecord("Actor interaction", actor));
  }
  for (const service of asArray(s2["services"])) {
    candidates.push(candidateFromRecord("Component abuse", service));
  }
  const components = s2["components"];
  if (isRecord(components)) {
    for (const [kind, list] of Object.entries(components)) {
      for (const component of asArray(list)) {
        candidates.push(candidateFromRecord(`${kind} abuse`, component));
      }
    }
  }
  return candidates;
}

function candidateFromRecord(kind: string, record: Record<string, unknown>): FallbackCandidate {
  const grounding = [
    ...strArray(record["grounding"]),
    ...strArray(record["evidence"]),
    ...strArray(record["evidence_anchors"]),
  ];
  const filePath = str(record["file"]) || str(record["file_path"]) || str(record["path"]);
  return {
    kind,
    id: str(record["id"]),
    name: str(record["name"]) || str(record["title"]) || str(record["id"]),
    description: str(record["description"]),
    riskLevel: str(record["risk_level"]) || str(record["riskLevel"]),
    gaps: strArray(record["gaps"]),
    controls: strArray(record["controls"]).concat(strArray(record["existing_controls"])),
    grounding,
    filePath,
  };
}

function parseEvidenceAnchors(candidate: FallbackCandidate): Array<Record<string, unknown>> {
  const anchors: Array<Record<string, unknown>> = [];
  for (const item of candidate.grounding) {
    const parsed = parseEvidenceString(item);
    if (parsed) anchors.push(parsed);
  }
  if (anchors.length === 0 && candidate.filePath) {
    anchors.push({
      file_path: candidate.filePath,
      start_line: 1,
      description: candidate.description || candidate.name || "Fallback S4 evidence",
    });
  }
  return anchors;
}

function parseEvidenceString(value: string): Record<string, unknown> | null {
  const match = value.match(/^([^:\s]+):(\d+)(?:-\d+)?\s*(?:[-:]\s*)?(.*)$/);
  if (!match) return null;
  return {
    file_path: match[1],
    start_line: Number(match[2]),
    description: match[3]?.trim() || "Fallback S4 evidence anchor",
  };
}

function inferStrideCategory(text: string): string {
  const lower = text.toLowerCase();
  if (
    lower.includes("pull_request_target") ||
    lower.includes("privilege") ||
    lower.includes("write token") ||
    lower.includes("force-land") ||
    lower.includes("override")
  ) {
    return "elevation-of-privilege";
  }
  if (
    lower.includes("secret") ||
    lower.includes("vault") ||
    lower.includes("token") ||
    lower.includes("credential")
  ) {
    return "information-disclosure";
  }
  if (lower.includes("spoof") || lower.includes("identity") || lower.includes("bot")) {
    return "spoofing";
  }
  if (lower.includes("audit") || lower.includes("log") || lower.includes("attribution")) {
    return "repudiation";
  }
  if (
    lower.includes("denial") ||
    lower.includes("dos") ||
    lower.includes("runner") ||
    lower.includes("queue") ||
    lower.includes("resource")
  ) {
    return "denial-of-service";
  }
  return "tampering";
}

function inferImpact(candidate: FallbackCandidate): string {
  const risk = candidate.riskLevel.toLowerCase();
  if (risk === "critical" || risk === "high" || risk === "medium" || risk === "low") return risk;
  const text = `${candidate.name} ${candidate.description}`.toLowerCase();
  if (text.includes("privilege") || text.includes("secret") || text.includes("write token")) {
    return "high";
  }
  return "medium";
}

function inferProbability(candidate: FallbackCandidate): number {
  switch (candidate.riskLevel.toLowerCase()) {
    case "critical":
      return 0.85;
    case "high":
      return 0.75;
    case "medium":
      return 0.55;
    case "low":
      return 0.25;
    default:
      return 0.5;
  }
}

function recommendedMitigations(stride: string): string[] {
  switch (stride) {
    case "elevation-of-privilege":
      return ["Gate privileged execution on trusted approvals and least-privilege tokens."];
    case "information-disclosure":
      return [
        "Minimize secret exposure and isolate credential-bearing steps from untrusted input.",
      ];
    case "spoofing":
      return ["Bind actions to verified identities and reject unauthenticated command sources."];
    case "repudiation":
      return ["Add tamper-resistant audit trails for privileged decisions and command sources."];
    case "denial-of-service":
      return ["Add concurrency, timeout, and resource controls around untrusted workloads."];
    default:
      return ["Validate and constrain untrusted inputs before they cross the trust boundary."];
  }
}

function mitreForStride(stride: string): string[] {
  switch (stride) {
    case "elevation-of-privilege":
      return ["T1068 - Exploitation for Privilege Escalation"];
    case "information-disclosure":
      return ["T1552 - Unsecured Credentials"];
    case "spoofing":
      return ["T1589 - Gather Victim Identity Information"];
    case "denial-of-service":
      return ["T1499 - Endpoint Denial of Service"];
    default:
      return ["T1565 - Data Manipulation"];
  }
}

function owaspForStride(stride: string): string {
  switch (stride) {
    case "elevation-of-privilege":
      return "A01:2021 - Broken Access Control";
    case "information-disclosure":
      return "A02:2021 - Cryptographic Failures";
    case "spoofing":
      return "A07:2021 - Identification and Authentication Failures";
    default:
      return "A04:2021 - Insecure Design";
  }
}

/** Normalize DFD element types from agent output to canonical form. */
function normalizeDfdType(t: string): string {
  switch (t.toLowerCase()) {
    case "external":
    case "external_entity":
      return "external-entity";
    case "datastore":
    case "data_store":
      return "data-store";
    case "dataflow":
    case "data_flow":
      return "data-flow";
    default:
      return t;
  }
}

/** Map Randori actor types to DFD element types. */
function actorTypeToDfdType(actorType: string): string {
  switch (actorType.toLowerCase()) {
    case "human":
    case "external-service":
    case "external":
      return "external-entity";
    case "automated":
    case "downstream-service":
    case "internal-service":
      return "process";
    default:
      return "external-entity";
  }
}

function componentKindToDfdType(kind: string): string {
  const lower = kind.toLowerCase();
  if (lower.includes("database") || lower.includes("store")) return "data-store";
  if (lower.includes("flow")) return "data-flow";
  return "process";
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function strArray(v: unknown): string[] {
  if (typeof v === "string" && v.trim()) return [v.trim()];
  if (!Array.isArray(v)) return [];
  return v.map((item) => String(item).trim()).filter(Boolean);
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asArray(v: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(v)) return [];
  return v.filter((item) => typeof item === "object" && item !== null) as Array<
    Record<string, unknown>
  >;
}

function asArrayOrRecordCollections(v: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(v)) return asArray(v);
  if (!isRecord(v)) return [];
  const out: Array<Record<string, unknown>> = [];
  for (const value of Object.values(v)) out.push(...asArray(value));
  return out;
}

function readJson(filePath: string): Record<string, unknown> | null {
  if (!existsSync(filePath)) return null;
  try {
    const raw = readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

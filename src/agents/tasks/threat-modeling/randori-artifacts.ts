/**
 * Reads Randori PASTA plugin output artifacts from randori-output/.
 * The plugin writes JSON stage files during execution; we read them after completion.
 */
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

export interface RandoriArtifacts {
  state: Record<string, unknown> | null;
  s2Scope: Record<string, unknown> | null;
  s3Decomposition: Record<string, unknown> | null;
  s4Threats: Record<string, unknown> | null;
}

export function readRandoriArtifacts(repoRoot: string, relativeOutputDir?: string): RandoriArtifacts {
  const outputDir = path.join(repoRoot, relativeOutputDir ?? "randori-output");
  return {
    state: readJson(path.join(outputDir, "randori-state.json")),
    s2Scope: readJson(path.join(outputDir, "pasta-s2.json")),
    s3Decomposition: readJson(path.join(outputDir, "pasta-s3.json")),
    s4Threats: readJson(path.join(outputDir, "pasta-s4.json")),
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
export function mergeRandoriStageOutputs(artifacts: RandoriArtifacts): Record<string, unknown> | null {
  // Build the DFD from S2+S3 regardless of whether S4 exists.
  // Previously this returned null when S4 was missing, which discarded
  // the entire DFD and left threat-hunt with no external entities.
  const s2 = artifacts.s2Scope;
  const s3 = artifacts.s3Decomposition;
  const s4 = artifacts.s4Threats;

  if (!s2 && !s3 && !s4) return null;

  const merged: Record<string, unknown> = s4 ? { ...s4 } : {};

  // S4 uses "threats" not "threat_scenarios" — normalize
  if (merged["threats"] && !merged["threat_scenarios"]) {
    merged["threat_scenarios"] = merged["threats"];
  }
  // Ensure threats array exists even without S4 so downstream gets a valid document
  if (!merged["threat_scenarios"] && !merged["threats"]) {
    merged["threat_scenarios"] = [];
    merged["threats"] = [];
  }

  // Build DFD from S2 actors/services + S3 dfd_elements + S3 trust boundaries
  const dfd: Record<string, unknown> = {};
  const seenIds = new Set<string>();
  const elements: Array<Record<string, unknown>> = [];

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
      if (!id || seenIds.has(id)) continue;
      seenIds.add(id);
      elements.push({
        id,
        type: "data-flow",
        name: str(flow["data"]) || `${str(flow["source"])} → ${str(flow["destination"])}`,
        description: str(flow["data"]),
        trust_zone: "cross-boundary",
        source: str(flow["source"]),
        target: str(flow["destination"]),
        protocol: str(flow["protocol"]),
        data_classification: str(flow["sensitivity"]),
      });
    }
  }

  // Incorporate S3's own dfd_elements (the agent often writes richer elements
  // directly in S3 that aren't present in S2's actor/service breakdown).
  if (s3) {
    for (const elem of asArray(s3["dfd_elements"])) {
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

    // Trust boundaries from S3
    const boundaries: Array<Record<string, unknown>> = [];
    for (const tb of asArray(s3["trust_boundaries"])) {
      boundaries.push({
        id: str(tb["id"]),
        name: str(tb["name"]),
        inner_zone: str(tb["name"]),
        outer_zone: "external",
        crossing_flows: asArray(tb["components"] ?? tb["crossing_components"]).map((c) => str(c)),
      });
    }
    dfd["trust_boundaries"] = boundaries;
  }

  dfd["elements"] = elements;
  merged["dfd"] = dfd;
  return merged;
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

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function asArray(v: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(v)) return [];
  return v.filter((item) => typeof item === "object" && item !== null) as Array<Record<string, unknown>>;
}

function readJson(filePath: string): Record<string, unknown> | null {
  if (!existsSync(filePath)) return null;
  try {
    const raw = readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}


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

export function readRandoriArtifacts(repoRoot: string): RandoriArtifacts {
  const outputDir = path.join(repoRoot, "randori-output");
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
  const s4 = artifacts.s4Threats;
  if (!s4) return null;

  const merged: Record<string, unknown> = { ...s4 };

  // S4 uses "threats" not "threat_scenarios" — normalize
  if (merged["threats"] && !merged["threat_scenarios"]) {
    merged["threat_scenarios"] = merged["threats"];
  }

  // Build synthetic DFD from S2 actors/services + S3 trust boundaries
  const dfd: Record<string, unknown> = {};

  // Synthesize DFD elements from S2 actors and services
  const elements: Array<Record<string, unknown>> = [];
  const s2 = artifacts.s2Scope;
  if (s2) {
    // Actors → external entities or processes
    for (const actor of asArray(s2["actors"])) {
      const type = actorTypeToDfdType(str(actor["type"]));
      elements.push({
        id: str(actor["id"]),
        type,
        name: str(actor["name"]),
        description: str(actor["description"]),
        trust_zone: str(actor["trust_level"]) || "external",
      });
    }
    // Services → processes
    for (const svc of asArray(s2["services"])) {
      elements.push({
        id: str(svc["id"]),
        type: "process",
        name: str(svc["name"]),
        description: str(svc["description"]),
        trust_zone: "internal",
      });
    }
    // Databases → data stores
    for (const db of asArray(s2["databases"])) {
      elements.push({
        id: str(db["id"]),
        type: "data-store",
        name: str(db["name"]),
        description: str(db["description"]),
        trust_zone: "internal",
      });
    }
    // Data flows
    for (const flow of asArray(s2["data_flows"])) {
      elements.push({
        id: str(flow["id"]),
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
  dfd["elements"] = elements;

  // Trust boundaries from S3
  const s3 = artifacts.s3Decomposition;
  if (s3) {
    const boundaries: Array<Record<string, unknown>> = [];
    for (const tb of asArray(s3["trust_boundaries"])) {
      boundaries.push({
        id: str(tb["id"]),
        name: str(tb["name"]),
        inner_zone: str(tb["name"]),
        outer_zone: "external",
        crossing_flows: asArray(tb["components"]).map((c) => str(c)),
      });
    }
    dfd["trust_boundaries"] = boundaries;
  }

  merged["dfd"] = dfd;
  return merged;
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

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type {
  DfdNode,
  StrideCategory,
  StrideThreat,
  ThreatModelDocument,
  ThreatModelNarrative,
} from "./agents/tasks/threat-modeling/types.js";

const PERSISTENT_THREAT_MODEL_PATH = ".kuzushi/threat-model.json";

export function createEmptyThreatModelDocument(now: Date = new Date()): ThreatModelDocument {
  return {
    version: "2.0",
    dfd: {
      nodes: [],
      flows: [],
      trustBoundaries: [],
    },
    threats: [],
    summary: {
      total: 0,
      bySeverity: {},
      byCategory: {
        spoofing: 0,
        tampering: 0,
        repudiation: 0,
        "information-disclosure": 0,
        "denial-of-service": 0,
        "elevation-of-privilege": 0,
      },
    },
    narrative: {
      overview: "",
      inputCategories: {
        attackerControlled: [],
        operatorControlled: [],
        developerControlled: [],
        externalServices: [],
        sandboxBoundary: [],
        assumptions: [],
      },
      attackerStories: [],
      criticalityBuckets: {
        critical: [],
        high: [],
        medium: [],
        low: [],
      },
      outOfScope: [],
    },
    userEdited: true,
    lastEditedAt: now.toISOString(),
  };
}

/**
 * Load the persistent threat model from .kuzushi/threat-model.json.
 * Falls back to per-run threat model if persistent doesn't exist.
 */
export function loadPersistentThreatModel(repoRoot: string): ThreatModelDocument | null {
  const persistentPath = path.join(repoRoot, PERSISTENT_THREAT_MODEL_PATH);
  if (!existsSync(persistentPath)) return null;
  try {
    return JSON.parse(readFileSync(persistentPath, "utf-8")) as ThreatModelDocument;
  } catch {
    return null;
  }
}

/**
 * Save a threat model to the persistent path .kuzushi/threat-model.json.
 * If the existing persistent model has userEdited=true, only update if force=true.
 */
export function savePersistentThreatModel(
  repoRoot: string,
  doc: ThreatModelDocument,
  force = false,
): boolean {
  const persistentPath = path.join(repoRoot, PERSISTENT_THREAT_MODEL_PATH);
  // Don't overwrite operator-edited models unless forced
  if (!force && existsSync(persistentPath)) {
    try {
      const existing = JSON.parse(readFileSync(persistentPath, "utf-8")) as ThreatModelDocument;
      if (existing.userEdited) return false;
    } catch {
      /* overwrite corrupt files */
    }
  }
  const dir = path.dirname(persistentPath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(persistentPath, `${JSON.stringify(doc, null, 2)}\n`, "utf-8");
  return true;
}

/**
 * Load a ThreatModelDocument from .kuzushi/runs/<runId>/threat-model.json.
 * Prefers the persistent threat model if it exists.
 * Returns null if neither file exists or is invalid.
 */
export function loadThreatModelDocument(
  repoRoot: string,
  runId: string,
): ThreatModelDocument | null {
  // Prefer persistent threat model
  const persistent = loadPersistentThreatModel(repoRoot);
  if (persistent) return persistent;

  // Fall back to per-run
  const tmPath = path.join(repoRoot, ".kuzushi", "runs", runId, "threat-model.json");
  if (!existsSync(tmPath)) return null;
  try {
    return JSON.parse(readFileSync(tmPath, "utf-8")) as ThreatModelDocument;
  } catch {
    return null;
  }
}

function formatStrideCategory(category: StrideCategory | string): string {
  switch (category) {
    case "spoofing":
      return "Spoofing";
    case "tampering":
      return "Tampering";
    case "repudiation":
      return "Repudiation";
    case "information-disclosure":
      return "Information Disclosure";
    case "denial-of-service":
      return "Denial of Service";
    case "elevation-of-privilege":
      return "Elevation of Privilege";
    default:
      return String(category);
  }
}

/**
 * Render a ThreatModelDocument as a human-readable Markdown context document.
 * Produces sections matching Codex Cyber output: Overview, Trust Boundaries
 * & Assumptions (with categorised inputs), Attack surface with attacker
 * stories, Criticality calibration, and Out-of-scope.
 *
 * When `doc.narrative` is present, the narrative fields take precedence and
 * the DFD/STRIDE data is rendered as secondary detail. When it is absent,
 * falls back to the original DFD/count-based rendering for back-compat with
 * older persisted `.kuzushi/threat-model.json` files.
 */
export function renderThreatModelContext(doc: ThreatModelDocument): string {
  const lines: string[] = [];
  const narrative = doc.narrative;

  // 1. Overview
  lines.push("### 1. Overview");
  lines.push("");
  if (narrative?.overview) {
    lines.push(narrative.overview);
    lines.push("");
  } else {
    renderOverviewFromDfd(doc, lines);
  }

  // 2. Trust boundaries and assumptions
  lines.push("### 2. Trust boundaries and assumptions");
  lines.push("");
  if (narrative) {
    renderInputCategories(narrative, lines);
  }
  renderDfdTrustBoundaries(doc, lines);
  if (!narrative) {
    renderTrustZoneFallback(doc, lines);
  }

  // 3. Attack surface, mitigations and attacker stories
  lines.push("### 3. Attack surface, mitigations and attacker stories");
  lines.push("");
  if (narrative && narrative.attackerStories.length > 0) {
    renderAttackerStories(narrative, lines);
  }
  renderStrideThreats(doc, lines, /* asSecondary */ Boolean(narrative));

  // 4. Criticality calibration
  lines.push("### 4. Criticality calibration");
  lines.push("");
  if (narrative) {
    renderCriticalityBuckets(narrative, lines);
  }
  renderSummaryCounts(doc, lines);

  // 5. Out-of-scope (only when narrative provides it)
  if (narrative && narrative.outOfScope.length > 0) {
    lines.push("### 5. Out-of-scope / less critical classes");
    lines.push("");
    for (const item of narrative.outOfScope) {
      lines.push(`- ${item}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

// ── Narrative-aware helpers ──

function renderInputCategories(narrative: ThreatModelNarrative, lines: string[]): void {
  const cats = narrative.inputCategories;
  const blocks: Array<[string, string[]]> = [
    ["Attacker-controlled inputs", cats.attackerControlled],
    ["Operator-controlled inputs", cats.operatorControlled],
    ["Developer-controlled inputs", cats.developerControlled],
    ["External services / dependencies", cats.externalServices],
    ["Sandbox boundary", cats.sandboxBoundary],
    ["Assumptions", cats.assumptions],
  ];
  for (const [heading, items] of blocks) {
    if (items.length === 0) continue;
    lines.push(`**${heading}**`);
    for (const item of items) lines.push(`- ${item}`);
    lines.push("");
  }
}

function renderAttackerStories(narrative: ThreatModelNarrative, lines: string[]): void {
  lines.push("**Attacker stories**");
  lines.push("");
  for (const story of narrative.attackerStories) {
    lines.push(`- **${story.title}** — ${story.narrative}`);
    if (story.mitigation) {
      lines.push(`  Mitigation: ${story.mitigation}`);
    }
    if (story.threatIds && story.threatIds.length > 0) {
      lines.push(`  Related threats: ${story.threatIds.join(", ")}`);
    }
  }
  lines.push("");
}

function renderCriticalityBuckets(narrative: ThreatModelNarrative, lines: string[]): void {
  const buckets = narrative.criticalityBuckets;
  const order: Array<[string, string[]]> = [
    ["Critical", buckets.critical],
    ["High", buckets.high],
    ["Medium", buckets.medium],
    ["Low", buckets.low],
  ];
  for (const [label, items] of order) {
    if (items.length === 0) continue;
    lines.push(`**${label}**`);
    for (const item of items) lines.push(`- ${item}`);
    lines.push("");
  }
}

// ── DFD fallback helpers (used when no narrative is present, or alongside it as detail) ──

function renderOverviewFromDfd(doc: ThreatModelDocument, lines: string[]): void {
  const nodes = dfdNodes(doc);
  const dataFlows = dfdFlows(doc);
  const processes = nodes.filter((e: DfdNode) => e.type === "process");
  const externalEntities = nodes.filter((e: DfdNode) => e.type === "external-entity");
  const dataStores = nodes.filter((e: DfdNode) => e.type === "data-store");

  if (processes.length > 0) {
    lines.push(
      `The application consists of ${processes.length} core process${processes.length > 1 ? "es" : ""}: ${processes.map((p: DfdNode) => p.name).join(", ")}.`,
    );
  }
  if (externalEntities.length > 0) {
    lines.push(
      `External actors: ${externalEntities.map((e: DfdNode) => `${e.name} (${e.description})`).join("; ")}.`,
    );
  }
  if (dataStores.length > 0) {
    lines.push(`Data stores: ${dataStores.map((d: DfdNode) => d.name).join(", ")}.`);
  }
  if (dataFlows.length > 0) {
    lines.push(`Data flows: ${dataFlows.length} identified.`);
  }
  lines.push("");
}

function renderDfdTrustBoundaries(doc: ThreatModelDocument, lines: string[]): void {
  const trustBoundaries = dfdTrustBoundaries(doc);
  if (trustBoundaries.length === 0) {
    if (!doc.narrative) {
      lines.push("No explicit trust boundaries identified.");
      lines.push("");
    }
    return;
  }
  lines.push("**DFD trust boundaries**");
  for (const boundary of trustBoundaries) {
    lines.push(`- **${boundary.name}**: ${boundary.innerZone} \u2194 ${boundary.outerZone}`);
    if (boundary.crossingFlowIds.length > 0) {
      lines.push(`  Crossing flows: ${boundary.crossingFlowIds.join(", ")}`);
    }
  }
  lines.push("");
}

function renderTrustZoneFallback(doc: ThreatModelDocument, lines: string[]): void {
  const externalEntities = dfdNodes(doc).filter((e: DfdNode) => e.type === "external-entity");
  const zones = new Set(externalEntities.map((e: DfdNode) => e.trustZone).filter(Boolean));
  if (zones.size === 0) return;
  lines.push("Trust zone assumptions:");
  for (const zone of zones) {
    const actors = externalEntities
      .filter((e: DfdNode) => e.trustZone === zone)
      .map((e: DfdNode) => e.name);
    lines.push(`- **${zone}**: ${actors.join(", ")}`);
  }
  lines.push("");
}

function dfdNodes(doc: ThreatModelDocument): DfdNode[] {
  if (Array.isArray(doc.dfd.nodes) && doc.dfd.nodes.length > 0) return doc.dfd.nodes;
  const elements = (Array.isArray(doc.dfd.elements) ? doc.dfd.elements : []) as Array<
    DfdNode | { id: string; type: "data-flow" }
  >;
  return elements.filter(
    (element) => (element as { type?: string }).type !== "data-flow",
  ) as DfdNode[];
}

function dfdFlows(doc: ThreatModelDocument): Array<{ id: string }> {
  if (Array.isArray(doc.dfd.flows) && doc.dfd.flows.length > 0) return doc.dfd.flows;
  const elements = (Array.isArray(doc.dfd.elements) ? doc.dfd.elements : []) as Array<
    DfdNode | { id: string; type: "data-flow" }
  >;
  return elements
    .filter((element) => (element as { type?: string }).type === "data-flow")
    .map((element) => ({
      id: element.id,
    }));
}

function dfdTrustBoundaries(doc: ThreatModelDocument): Array<{
  id: string;
  name: string;
  innerZone: string;
  outerZone: string;
  crossingFlowIds: string[];
}> {
  return (doc.dfd.trustBoundaries ?? []).map((boundary) => {
    const legacy = boundary as typeof boundary & { crossingFlows?: string[] };
    return {
      id: boundary.id,
      name: boundary.name,
      innerZone: boundary.innerZone,
      outerZone: boundary.outerZone,
      crossingFlowIds: boundary.crossingFlowIds ?? legacy.crossingFlows ?? [],
    };
  });
}

function renderStrideThreats(
  doc: ThreatModelDocument,
  lines: string[],
  asSecondary: boolean,
): void {
  if (doc.threats.length === 0) {
    if (!asSecondary) {
      lines.push("No STRIDE threats identified.");
      lines.push("");
    }
    return;
  }
  if (asSecondary) {
    lines.push("**STRIDE detail**");
    lines.push("");
  }
  const byCategory = new Map<StrideCategory, StrideThreat[]>();
  for (const threat of doc.threats) {
    const existing = byCategory.get(threat.category) ?? [];
    existing.push(threat);
    byCategory.set(threat.category, existing);
  }
  for (const [category, threats] of byCategory) {
    lines.push(
      `**${formatStrideCategory(category)}** (${threats.length} threat${threats.length > 1 ? "s" : ""}):`,
    );
    lines.push("");
    // Cap per-category to avoid overwhelming output
    for (const threat of threats.slice(0, 10)) {
      lines.push(`- **${threat.title}** [${threat.impact}]`);
      lines.push(`  Attack vector: ${threat.attackVector}`);
      if (threat.existingMitigations.length > 0) {
        lines.push(`  Existing mitigations: ${threat.existingMitigations.join("; ")}`);
      }
      if (threat.missingMitigations.length > 0) {
        lines.push(`  Missing mitigations: ${threat.missingMitigations.join("; ")}`);
      }
      if (threat.relatedCwe.length > 0) {
        lines.push(`  CWE: ${threat.relatedCwe.join(", ")}`);
      }
    }
    lines.push("");
  }
}

function renderSummaryCounts(doc: ThreatModelDocument, lines: string[]): void {
  if (!doc.summary) return;
  lines.push(`Total threats: ${doc.summary.total}`);
  lines.push("");
  if (Object.keys(doc.summary.bySeverity).length > 0) {
    lines.push("By severity:");
    for (const [severity, count] of Object.entries(doc.summary.bySeverity)) {
      if (count > 0) lines.push(`- ${severity}: ${count}`);
    }
    lines.push("");
  }
  if (Object.keys(doc.summary.byCategory).length > 0) {
    lines.push("By STRIDE category:");
    for (const [cat, count] of Object.entries(doc.summary.byCategory)) {
      if (Number(count) > 0)
        lines.push(`- ${formatStrideCategory(cat as StrideCategory)}: ${count}`);
    }
    lines.push("");
  }
}

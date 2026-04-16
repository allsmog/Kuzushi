import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type {
  ThreatModelDocument,
  DfdElement,
  TrustBoundary,
  StrideThreat,
  StrideCategory,
} from "./agents/tasks/threat-modeling/types.js";

/**
 * Load a ThreatModelDocument from .kuzushi/runs/<runId>/threat-model.json.
 * Returns null if the file doesn't exist or is invalid.
 */
export function loadThreatModelDocument(
  repoRoot: string,
  runId: string,
): ThreatModelDocument | null {
  const tmPath = path.join(
    repoRoot,
    ".kuzushi",
    "runs",
    runId,
    "threat-model.json",
  );
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
 * Produces sections matching Codex Cyber output: Overview, Trust Boundaries,
 * Attack Surface, Criticality Calibration.
 */
export function renderThreatModelContext(doc: ThreatModelDocument): string {
  const lines: string[] = [];

  // 1. Overview
  lines.push("### 1. Overview");
  lines.push("");

  const processes = doc.dfd.elements.filter(
    (e: DfdElement) => e.type === "process",
  );
  const externalEntities = doc.dfd.elements.filter(
    (e: DfdElement) => e.type === "external-entity",
  );
  const dataStores = doc.dfd.elements.filter(
    (e: DfdElement) => e.type === "data-store",
  );
  const dataFlows = doc.dfd.elements.filter(
    (e: DfdElement) => e.type === "data-flow",
  );

  if (processes.length > 0) {
    lines.push(
      `The application consists of ${processes.length} core process${processes.length > 1 ? "es" : ""}: ${processes.map((p: DfdElement) => p.name).join(", ")}.`,
    );
  }
  if (externalEntities.length > 0) {
    lines.push(
      `External actors: ${externalEntities.map((e: DfdElement) => `${e.name} (${e.description})`).join("; ")}.`,
    );
  }
  if (dataStores.length > 0) {
    lines.push(
      `Data stores: ${dataStores.map((d: DfdElement) => d.name).join(", ")}.`,
    );
  }
  if (dataFlows.length > 0) {
    lines.push(`Data flows: ${dataFlows.length} identified.`);
  }
  lines.push("");

  // 2. Trust boundaries & assumptions
  lines.push("### 2. Trust boundaries and assumptions");
  lines.push("");
  if (doc.dfd.trustBoundaries.length > 0) {
    for (const boundary of doc.dfd.trustBoundaries) {
      lines.push(
        `- **${boundary.name}**: ${boundary.innerZone} \u2194 ${boundary.outerZone}`,
      );
      if (boundary.crossingFlows.length > 0) {
        lines.push(
          `  Crossing flows: ${boundary.crossingFlows.join(", ")}`,
        );
      }
    }
  } else {
    lines.push("No explicit trust boundaries identified.");
  }
  lines.push("");

  // Trust zone assumptions from external entities
  const zones = new Set(
    externalEntities.map((e: DfdElement) => e.trustZone).filter(Boolean),
  );
  if (zones.size > 0) {
    lines.push("Trust zone assumptions:");
    for (const zone of zones) {
      const actors = externalEntities
        .filter((e: DfdElement) => e.trustZone === zone)
        .map((e: DfdElement) => e.name);
      lines.push(`- **${zone}**: ${actors.join(", ")}`);
    }
    lines.push("");
  }

  // 3. Attack surface & mitigations
  lines.push("### 3. Attack surface, mitigations and attacker stories");
  lines.push("");
  if (doc.threats.length > 0) {
    // Group by STRIDE category
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
          lines.push(
            `  Existing mitigations: ${threat.existingMitigations.join("; ")}`,
          );
        }
        if (threat.missingMitigations.length > 0) {
          lines.push(
            `  Missing mitigations: ${threat.missingMitigations.join("; ")}`,
          );
        }
        if (threat.relatedCwe.length > 0) {
          lines.push(`  CWE: ${threat.relatedCwe.join(", ")}`);
        }
      }
      lines.push("");
    }
  } else {
    lines.push("No STRIDE threats identified.");
    lines.push("");
  }

  // 4. Criticality calibration
  lines.push("### 4. Criticality calibration");
  lines.push("");
  if (doc.summary) {
    lines.push(`Total threats: ${doc.summary.total}`);
    lines.push("");
    if (Object.keys(doc.summary.bySeverity).length > 0) {
      lines.push("By severity:");
      for (const [severity, count] of Object.entries(
        doc.summary.bySeverity,
      )) {
        if (count > 0) lines.push(`- ${severity}: ${count}`);
      }
      lines.push("");
    }
    if (Object.keys(doc.summary.byCategory).length > 0) {
      lines.push("By STRIDE category:");
      for (const [cat, count] of Object.entries(doc.summary.byCategory)) {
        if (Number(count) > 0)
          lines.push(
            `- ${formatStrideCategory(cat as StrideCategory)}: ${count}`,
          );
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}

/**
 * Pure selectors over the threat-model document, extracted out of
 * `threat-hunt.ts` so the UI layer can call them without importing the
 * agent-runtime.
 *
 * `extractActorsWithThreats` is the canonical "which DFD external entities
 * are worth hunting" query — it ranks actors by their HIGH/CRITICAL STRIDE
 * threat count, returning both the prioritised list and the unfiltered set
 * for read-out in UI surfaces (e.g. "3 ready · 1 deferred").
 */

import { resolveThreatModelOutput } from "../../agents/tasks/threat-model-guidance.js";
import type {
  DfdElement,
  StrideThreat,
  ThreatModelDocument,
} from "../../agents/tasks/threat-modeling/types.js";
import { isRecord } from "../../utils.js";

/** One actor row paired with its HIGH/CRITICAL threats. */
export interface ActorWithThreats {
  actor: DfdElement;
  threats: StrideThreat[];
}

export interface ExtractActorsResult {
  /** Actors with ≥1 HIGH/CRITICAL threat, sorted by criticality. */
  prioritized: ActorWithThreats[];
  /** Every external-entity actor in the DFD, regardless of threat coverage. */
  allActors: DfdElement[];
}

/**
 * Read the canonical Randori document out of the upstream-outputs map and
 * partition external-entity actors by whether they have at least one HIGH
 * or CRITICAL STRIDE threat. The UI uses both lists; the runtime only
 * cares about the prioritized one.
 */
export function extractActorsWithThreats(
  upstreamOutputs: ReadonlyMap<string, unknown>,
): ExtractActorsResult {
  const raw = resolveThreatModelOutput(upstreamOutputs as Map<string, unknown>);
  if (!isRecord(raw) || !isRecord(raw["document"])) return { prioritized: [], allActors: [] };
  const doc = raw["document"] as unknown as ThreatModelDocument;
  if (!doc.dfd?.elements || !Array.isArray(doc.dfd.elements)) {
    return { prioritized: [], allActors: [] };
  }

  const allActors = doc.dfd.elements.filter((el) => el.type === "external-entity");
  const threats: StrideThreat[] = Array.isArray(doc.threats) ? doc.threats : [];

  const highThreats = new Map<string, StrideThreat[]>();
  for (const threat of threats) {
    if (threat.impact !== "critical" && threat.impact !== "high") continue;
    const bucket = highThreats.get(threat.elementId) ?? [];
    bucket.push(threat);
    highThreats.set(threat.elementId, bucket);
  }

  const prioritized = allActors
    .filter((el) => (highThreats.get(el.id)?.length ?? 0) > 0)
    .map((el) => ({ actor: el, threats: highThreats.get(el.id)! }))
    .sort((a, b) => {
      const critA = a.threats.filter((t) => t.impact === "critical").length;
      const critB = b.threats.filter((t) => t.impact === "critical").length;
      if (critB !== critA) return critB - critA;
      return b.threats.length - a.threats.length;
    });

  return { prioritized, allActors };
}

/**
 * Pure-document overload — accepts a ThreatModelDocument directly so the
 * UI can call this against `shell.threatModel` without first stuffing the
 * document into a `Map<string, unknown>`.
 */
export function actorsFromDocument(
  doc: ThreatModelDocument | null | undefined,
): ExtractActorsResult {
  if (!doc?.dfd?.elements || !Array.isArray(doc.dfd.elements)) {
    return { prioritized: [], allActors: [] };
  }
  const wrapper = new Map<string, unknown>([["threat-model-randori", { document: doc }]]);
  return extractActorsWithThreats(wrapper);
}

/**
 * Pure selectors over the threat-model document, extracted out of
 * `carlini-threat-hunt.ts` so the UI layer can call them without importing the
 * agent-runtime.
 *
 * `extractActorsWithThreats` is the canonical "which DFD external entities
 * are worth hunting" query — it ranks actors by their HIGH/CRITICAL STRIDE
 * threat count, returning both the prioritised list and the unfiltered set
 * for read-out in UI surfaces (e.g. "3 ready · 1 deferred").
 */

import { resolveThreatModelOutput } from "../../agents/tasks/threat-model-guidance.js";
import type {
  DfdFlow,
  DfdNode,
  StrideThreat,
  ThreatModelDocument,
} from "../../agents/tasks/threat-modeling/types.js";
import { isRecord } from "../../utils.js";

/** One actor row paired with its HIGH/CRITICAL threats. */
export interface ActorWithThreats {
  actor: DfdNode;
  threats: StrideThreat[];
  flows: DfdFlow[];
}

export interface ExtractActorsResult {
  /** Actors with ≥1 HIGH/CRITICAL threat, sorted by criticality. */
  prioritized: ActorWithThreats[];
  /** Every external-entity actor in the DFD, regardless of threat coverage. */
  allActors: DfdNode[];
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
  return actorsFromDocument(doc);
}

/**
 * Pure-document overload — accepts a ThreatModelDocument directly so the
 * UI can call this against `shell.threatModel` without first stuffing the
 * document into a `Map<string, unknown>`.
 */
export function actorsFromDocument(
  doc: ThreatModelDocument | null | undefined,
): ExtractActorsResult {
  if (!doc?.dfd?.nodes || !Array.isArray(doc.dfd.nodes)) {
    return { prioritized: [], allActors: [] };
  }
  const nodes = doc.dfd.nodes;
  const flows = Array.isArray(doc.dfd.flows) ? doc.dfd.flows : [];
  const allActors = nodes.filter((el) => el.type === "external-entity");
  const actorIds = new Set(allActors.map((actor) => actor.id));
  const actorsById = new Map(allActors.map((actor) => [actor.id, actor]));
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const flowById = new Map(flows.map((flow) => [flow.id, flow]));
  const threats: StrideThreat[] = Array.isArray(doc.threats) ? doc.threats : [];

  const highThreats = new Map<string, StrideThreat[]>();
  for (const threat of threats) {
    if (threat.impact !== "critical" && threat.impact !== "high") continue;
    for (const actorId of resolveThreatActorIds(threat, actorIds, actorsById, nodeById, flowById)) {
      const bucket = highThreats.get(actorId) ?? [];
      bucket.push(threat);
      highThreats.set(actorId, bucket);
    }
  }

  const prioritized = allActors
    .filter((el) => (highThreats.get(el.id)?.length ?? 0) > 0)
    .map((el) => ({
      actor: el,
      threats: highThreats.get(el.id)!,
      flows: flowsForActor(el.id, highThreats.get(el.id)!, flows, flowById),
    }))
    .sort((a, b) => {
      const critA = a.threats.filter((t) => t.impact === "critical").length;
      const critB = b.threats.filter((t) => t.impact === "critical").length;
      if (critB !== critA) return critB - critA;
      return b.threats.length - a.threats.length;
    });

  return { prioritized, allActors };
}

function resolveThreatActorIds(
  threat: StrideThreat,
  actorIds: ReadonlySet<string>,
  actorsById: ReadonlyMap<string, DfdNode>,
  nodeById: ReadonlyMap<string, DfdNode>,
  flowById: ReadonlyMap<string, DfdFlow>,
): string[] {
  const direct = unique((threat.actorIds ?? []).filter((actorId) => actorIds.has(actorId)));
  if (direct.length > 0) return direct;

  const semantic = semanticActorIds(threat, actorsById);
  if (semantic.length > 0) return semantic;

  const fromFlows: string[] = [];
  for (const flowId of threat.flowIds ?? []) {
    const flow = flowById.get(flowId);
    if (!flow) continue;
    for (const endpoint of [flow.sourceId, flow.targetId]) {
      if (actorIds.has(endpoint)) fromFlows.push(endpoint);
    }
  }
  const flowActors = unique(fromFlows);
  if (flowActors.length > 0) return flowActors;

  const targetActors = unique(
    [...(threat.targetElementIds ?? []), ...(threat.entrypointIds ?? [])].filter((id) => {
      const node = nodeById.get(id);
      return node?.type === "external-entity";
    }),
  );
  return targetActors;
}

function semanticActorIds(
  threat: StrideThreat,
  actorsById: ReadonlyMap<string, DfdNode>,
): string[] {
  const haystack = threatSearchText(threat);
  if (!haystack) return [];

  const scored: Array<{ id: string; score: number }> = [];
  for (const actor of actorsById.values()) {
    const score = actorSemanticScore(actor, haystack);
    if (score >= 2) scored.push({ id: actor.id, score });
  }

  scored.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
  return scored.slice(0, 3).map((item) => item.id);
}

function threatSearchText(threat: StrideThreat): string {
  const refs = [
    ...(threat.sources ?? []),
    ...(threat.sinks ?? []),
    ...(threat.guards ?? []),
    ...(threat.sanitizers ?? []),
  ];
  return [
    threat.title,
    threat.description,
    threat.attackVector,
    ...(threat.requiredCapabilities ?? []),
    ...(threat.preconditions ?? []),
    ...refs.flatMap((ref) => [ref.name, ref.kind, ref.elementId, ref.description, ref.filePath]),
    ...(threat.evidenceAnchors ?? []).flatMap((anchor) => [
      anchor.filePath,
      anchor.symbol,
      anchor.description,
      anchor.snippet,
    ]),
  ]
    .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
    .join(" ")
    .toLowerCase();
}

function actorSemanticScore(actor: DfdNode, haystack: string): number {
  const label = `${actor.id} ${actor.name} ${actor.description}`.toLowerCase();
  let score = 0;

  if (haystack.includes(actor.id.toLowerCase())) score += 5;
  for (const token of actorTokens(actor)) {
    if (haystack.includes(token)) score += 1;
  }

  if (/\b(pr|pull request|fork|branch|contributor)\b/.test(haystack)) {
    if (/\b(pr author|fork|contributor|developer)\b/.test(label)) score += 4;
  }
  if (/\b(comment|issue comment|review comment|slash command)\b/.test(haystack)) {
    if (/\bcommenter|comment|issue\b/.test(label)) score += 4;
  }
  if (/\b(admin|owner|maintainer|platform)\b/.test(haystack)) {
    if (/\badmin|owner|maintainer|platform\b/.test(label)) score += 3;
  }
  if (/\b(bot|github app|app token)\b/.test(haystack)) {
    if (/\bbot|github app|app\b/.test(label)) score += 2;
  }

  return score;
}

function actorTokens(actor: DfdNode): string[] {
  const stop = new Set([
    "actor",
    "api",
    "app",
    "bot",
    "com",
    "external",
    "github",
    "http",
    "https",
    "internal",
    "service",
    "user",
  ]);
  return unique(
    `${actor.id} ${actor.name} ${actor.description}`
      .toLowerCase()
      .split(/[^a-z0-9.-]+/g)
      .filter((token) => token.length >= 4 && !stop.has(token)),
  );
}

function flowsForActor(
  actorId: string,
  threats: StrideThreat[],
  allFlows: DfdFlow[],
  flowById: ReadonlyMap<string, DfdFlow>,
): DfdFlow[] {
  const linked = new Map<string, DfdFlow>();
  for (const flow of allFlows) {
    if (flow.sourceId === actorId || flow.targetId === actorId) {
      linked.set(flow.id, flow);
    }
  }
  for (const threat of threats) {
    for (const flowId of threat.flowIds ?? []) {
      const flow = flowById.get(flowId);
      if (flow) linked.set(flow.id, flow);
    }
  }
  return [...linked.values()];
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim().length > 0))];
}

/**
 * Triage dispatch logic extracted from PipelineOrchestrator.
 *
 * Manages the triage queue: dispatching findings for triage,
 * handling results/errors, and tracking dead-letter findings.
 */

import type { Finding } from "../../scanners/types.js";
import { updateRunCost } from "../../store.js";
import type { TriageResult } from "../../types.js";
import { isRecord, normalizeCostUsd } from "../../utils.js";
import { createEvent } from "../helpers.js";
import { getRunSignal } from "../run-signals.js";
import type { MessageBus } from "../types.js";
import type { OrchestratorDeps, RunState } from "./types.js";

/**
 * Collect the threat IDs present in the threat-model output so downstream
 * workers can cross-check `source_threat_ids` returned by triage and drop
 * hallucinated IDs that don't exist in the actual model.
 */
export function collectKnownThreatIds(taskOutputs: Map<string, unknown>): string[] {
  const raw = taskOutputs.get("threat-model-randori");
  if (!isRecord(raw)) return [];
  const threats = Array.isArray(raw["threats"]) ? raw["threats"] : [];
  const ids: string[] = [];
  for (const t of threats) {
    if (!isRecord(t)) continue;
    const id = typeof t["id"] === "string" ? t["id"].trim() : "";
    if (id) ids.push(id);
  }
  return ids;
}

/**
 * Extract a rich threat model context from upstream task outputs
 * to provide application-context for triage/verification decisions.
 *
 * Produces a structured document matching Codex Cyber output fidelity:
 * trust boundaries, attacker-controlled inputs, attack surface with
 * mitigations, and criticality calibration.
 */
export function buildThreatModelSummary(taskOutputs: Map<string, unknown>): string | undefined {
  const raw = taskOutputs.get("threat-model-randori");
  if (!isRecord(raw)) return undefined;

  const parts: string[] = [];

  const dfd = isRecord(raw["dfd"]) ? raw["dfd"] : undefined;
  const elements = dfd && Array.isArray(dfd["elements"]) ? dfd["elements"] : [];
  const trustBoundaries =
    dfd && Array.isArray(dfd["trustBoundaries"]) ? dfd["trustBoundaries"] : [];
  const threats = Array.isArray(raw["threats"]) ? raw["threats"] : [];

  // ── 1. Trust boundaries & input classification ──
  const externalEntities = elements
    .filter((e: unknown) => isRecord(e) && e["type"] === "external-entity")
    .map((e: unknown) => {
      if (!isRecord(e)) return null;
      return {
        name: String(e["name"] ?? ""),
        description: String(e["description"] ?? ""),
        trustZone: String(e["trustZone"] ?? ""),
      };
    })
    .filter((e): e is { name: string; description: string; trustZone: string } => !!e?.name);

  if (externalEntities.length > 0 || trustBoundaries.length > 0) {
    const tbLines = ["### Trust boundaries and assumptions"];
    if (trustBoundaries.length > 0) {
      for (const b of trustBoundaries) {
        if (!isRecord(b)) continue;
        const name = String(b["name"] ?? "");
        const inner = String(b["innerZone"] ?? "");
        const outer = String(b["outerZone"] ?? "");
        if (name) tbLines.push(`- **${name}**: ${inner} ↔ ${outer}`);
      }
    }
    if (externalEntities.length > 0) {
      tbLines.push("");
      tbLines.push("Attacker-controlled inputs:");
      for (const entity of externalEntities) {
        tbLines.push(`- **${entity.name}** (${entity.trustZone}): ${entity.description}`);
      }
    }
    parts.push(tbLines.join("\n"));
  }

  // ── 2. Attack surface with mitigations ──
  if (threats.length > 0) {
    const surfaceLines = ["### Attack surface, mitigations and attacker stories"];
    // Group threats by STRIDE category
    const byCategory = new Map<string, Array<Record<string, unknown>>>();
    for (const t of threats) {
      if (!isRecord(t)) continue;
      const cat = String(t["category"] ?? "unknown");
      let list = byCategory.get(cat);
      if (!list) {
        list = [];
        byCategory.set(cat, list);
      }
      list.push(t);
    }

    for (const [category, catThreats] of byCategory) {
      surfaceLines.push(`\n**${formatCategory(category)}** (${catThreats.length}):`);
      for (const t of catThreats.slice(0, 8)) {
        const title = String(t["title"] ?? "");
        const impact = String(t["impact"] ?? "");
        const vector = String(t["attackVector"] ?? "");
        const id = String(t["id"] ?? "");
        surfaceLines.push(`- [${id}] **${title}** [${impact}]`);
        if (vector) surfaceLines.push(`  Attack vector: ${vector}`);
        const existing = Array.isArray(t["existingMitigations"]) ? t["existingMitigations"] : [];
        if (existing.length > 0) {
          surfaceLines.push(`  Existing mitigations: ${existing.map(String).join("; ")}`);
        }
        const missing = Array.isArray(t["missingMitigations"]) ? t["missingMitigations"] : [];
        if (missing.length > 0) {
          surfaceLines.push(`  Missing mitigations: ${missing.map(String).join("; ")}`);
        }
        const cwes = Array.isArray(t["relatedCwe"]) ? t["relatedCwe"] : [];
        if (cwes.length > 0) {
          surfaceLines.push(`  CWE: ${cwes.map(String).join(", ")}`);
        }
      }
    }
    parts.push(surfaceLines.join("\n"));
  }

  // ── 3. Criticality calibration ──
  const summary = isRecord(raw["summary"]) ? raw["summary"] : undefined;
  if (summary) {
    const total = Number(summary["total"] ?? 0);
    const bySeverity = isRecord(summary["bySeverity"]) ? summary["bySeverity"] : {};
    const calLines = ["### Criticality calibration"];
    calLines.push(`Total threats: ${total}`);
    const sevEntries = Object.entries(bySeverity).filter(([, v]) => Number(v) > 0);
    if (sevEntries.length > 0) {
      for (const [sev, count] of sevEntries) {
        calLines.push(`- ${sev}: ${count}`);
      }
    }
    parts.push(calLines.join("\n"));
  }

  // ── 4. Offensive tool detection ──
  const allText = JSON.stringify(raw).toLowerCase();
  const offensivePatterns = [
    "pentest",
    "offensive",
    "red team",
    "tunneling",
    "pivoting",
    "c2",
    "implant",
    "exploitation framework",
    "attack tool",
  ];
  const isOffensiveTool = offensivePatterns.some((p) => allText.includes(p));
  if (isOffensiveTool) {
    parts.push(
      "Application type: OFFENSIVE SECURITY / PENTEST TOOL — findings about missing authentication, encryption, or access control may be BY DESIGN for this tool's intended use case. Focus on bugs that harm the tool's OPERATOR (crashes, data races, credential leaks) rather than design choices about target interaction.",
    );
  }

  return parts.length > 0 ? parts.join("\n\n") : undefined;
}

function formatCategory(cat: string): string {
  switch (cat) {
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
      return cat;
  }
}

export function handleTriageResult(
  state: RunState,
  runId: string,
  finding: Finding,
  result: TriageResult,
  costUsd: number | undefined,
  shouldVerifyFinding: (state: RunState, finding: Finding, triageResult: TriageResult) => boolean,
  deps: OrchestratorDeps,
): void {
  state.inFlight = Math.max(0, state.inFlight - 1);
  state.triaged += 1;
  const cost = normalizeCostUsd(costUsd);
  state.totalCostUsd += cost;

  if (shouldVerifyFinding(state, finding, result)) {
    state.verifyCandidates.push({ finding, triageResult: result });
  }

  try {
    updateRunCost(deps.db, state.checkpointRunId, cost);
  } catch {
    // Cost persistence is best-effort.
  }
}

export function handleTriageError(
  state: RunState,
  error: string,
  finding: Finding,
  costUsd: number | undefined,
  attempts: number | undefined,
  index: number | undefined,
  total: number | undefined,
  deps: OrchestratorDeps,
): void {
  state.inFlight = Math.max(0, state.inFlight - 1);
  state.triageErrors += 1;
  const cost = normalizeCostUsd(costUsd);
  state.totalCostUsd += cost;

  const fp = finding.fingerprint;
  const maxRetries = state.config.maxTriageRetries ?? 2;
  const priorAttempts = state.triageAttempts.get(fp) ?? 0;
  const totalAttempts = Math.max(priorAttempts, attempts ?? 1);
  state.triageAttempts.set(fp, totalAttempts);

  if (totalAttempts >= maxRetries) {
    state.deadLetterFindings.push({
      fingerprint: fp,
      error,
      attempts: totalAttempts,
      lastAttempt: new Date().toISOString(),
    });
  } else {
    state.triageErrors -= 1;
    state.triageQueue.push({
      finding,
      index: index ?? 0,
      total: total ?? state.triageTotal,
    });
  }

  try {
    updateRunCost(deps.db, state.checkpointRunId, cost);
  } catch {
    // Cost persistence is best-effort.
  }
}

export function isTriageDone(state: RunState): boolean {
  const processed = state.triaged + state.triageErrors;
  return (
    state.triageTotal > 0 &&
    processed >= state.triageTotal &&
    state.inFlight === 0 &&
    !state.reportRequested
  );
}

export async function dispatchTriage(
  state: RunState,
  runId: string,
  bus: MessageBus,
  isBudgetExceeded: (state: RunState) => boolean,
  emitBudgetCheck: (state: RunState, runId: string) => Promise<void>,
  emitBudgetExceeded: (state: RunState, runId: string) => Promise<void>,
  publishQueueDepth: (state: RunState, runId: string) => Promise<void>,
): Promise<void> {
  if (state.dispatching) return;

  state.dispatching = true;
  try {
    const concurrency = normalizeConcurrency(state.config.triageConcurrency);
    const runSignal = getRunSignal(runId);

    while (state.inFlight < concurrency && state.queueCursor < state.triageQueue.length) {
      // Fail-fast: the run's abort signal flips on fatal pipeline:error or
      // operator Ctrl+C. Stop dispatching so we don't burn LLM cost on
      // findings whose results will be discarded.
      if (runSignal?.aborted) break;
      await emitBudgetCheck(state, runId);
      if (isBudgetExceeded(state)) {
        await emitBudgetExceeded(state, runId);
        break;
      }
      const item = state.triageQueue[state.queueCursor];
      state.queueCursor += 1;
      state.inFlight += 1;

      await bus.publish(
        createEvent("triage:finding-queued", runId, {
          context: state.context,
          finding: item.finding,
          repoContext: state.repoContext,
          enrichedContext: state.enrichedRepoContext,
          precedents: state.precedents,
          threatModelSummary: buildThreatModelSummary(state.taskOutputs),
          knownThreatIds: collectKnownThreatIds(state.taskOutputs),
          operatorContext: state.operatorContext,
          index: item.index,
          total: item.total,
        }),
      );
    }

    await publishQueueDepth(state, runId);
  } finally {
    state.dispatching = false;
  }
}

export async function publishTriageQueueDepth(
  state: RunState,
  runId: string,
  bus: MessageBus,
): Promise<void> {
  const queued = Math.max(0, state.triageQueue.length - state.queueCursor);
  const processed = state.triaged + state.triageErrors;

  await bus.publish(
    createEvent("triage:queue-depth", runId, {
      context: state.context,
      queued,
      inFlight: state.inFlight,
      processed,
      total: state.triageTotal,
    }),
  );
}

function normalizeConcurrency(raw: number): number {
  if (!Number.isFinite(raw) || raw < 1) return 1;
  return Math.floor(raw);
}

/**
 * Operator scan context — persistence, auto-generation, and prompt formatting.
 *
 * The operator scan context captures trust, scope, architecture, and historical
 * feedback declared (or auto-detected and then reviewed) by the operator.
 * It persists to `.kuzushi/scan-context.json` and is injected into
 * triage/verification system prompts.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { ThreatModelDocument } from "./agents/tasks/threat-modeling/types.js";
import type {
  ApplicationModel,
  EnrichedRepoContext,
  OperatorContextItem,
  OperatorScanContext,
  RepoContext,
  Verdict,
} from "./types.js";

export const PERSISTENT_CONTEXT_PATH = ".kuzushi/scan-context.json";
const CONTEXT_VERSION = "1";

// ── Persistence ──

export function loadOperatorScanContext(repoRoot: string): OperatorScanContext | null {
  const contextPath = path.join(repoRoot, PERSISTENT_CONTEXT_PATH);
  if (!existsSync(contextPath)) return null;
  try {
    return JSON.parse(readFileSync(contextPath, "utf-8")) as OperatorScanContext;
  } catch {
    return null;
  }
}

export function saveOperatorScanContext(repoRoot: string, ctx: OperatorScanContext): void {
  const contextPath = path.join(repoRoot, PERSISTENT_CONTEXT_PATH);
  const dir = path.dirname(contextPath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(contextPath, `${JSON.stringify(ctx, null, 2)}\n`, "utf-8");
}

// ── Auto-generation ──

function item<T = string>(value: T): OperatorContextItem<T> {
  return { value, status: "skipped" };
}

function dedupe(arr: string[]): string[] {
  return [...new Set(arr.filter(Boolean))];
}

export interface GenerationSources {
  repoContext?: RepoContext;
  enrichedContext?: EnrichedRepoContext;
  appModel?: ApplicationModel;
  threatModel?: ThreatModelDocument;
  historicalFindings?: Array<{ fingerprint: string; ruleId: string; verdict: Verdict }>;
}

export function generateOperatorContextFromOutputs(
  sources: GenerationSources,
): OperatorScanContext {
  const { repoContext, enrichedContext, appModel, threatModel, historicalFindings } = sources;

  // ── Trust ──
  const infrastructure: string[] = [];
  if (repoContext?.ormOrDb) infrastructure.push(...repoContext.ormOrDb);
  if (appModel?.dataStores) {
    for (const ds of appModel.dataStores) {
      infrastructure.push(`${ds.kind}: ${ds.name}`);
    }
  }

  const defenses: string[] = [];
  if (repoContext?.sanitizationLibs) defenses.push(...repoContext.sanitizationLibs);
  if (enrichedContext?.enrichment?.customMiddleware) {
    for (const mw of enrichedContext.enrichment.customMiddleware) {
      if (/security|auth|csrf|cors|rate.?limit|helmet/i.test(mw.purpose)) {
        defenses.push(`${mw.name} (${mw.purpose})`);
      }
    }
  }

  const mitigations: string[] = [];
  if (threatModel?.threats) {
    for (const t of threatModel.threats) {
      mitigations.push(...t.existingMitigations);
    }
  }
  if (threatModel?.confirmedMitigations) mitigations.push(...threatModel.confirmedMitigations);

  // ── Scope ──
  const highValuePaths: string[] = [];
  if (repoContext?.entryPoints) highValuePaths.push(...repoContext.entryPoints);
  if (enrichedContext?.enrichment?.trustBoundaries) {
    for (const tb of enrichedContext.enrichment.trustBoundaries) {
      if (tb.entryPoints) highValuePaths.push(...tb.entryPoints);
    }
  }

  const sensitiveDataTags: Array<{
    dataType: string;
    sensitivity: "public" | "internal" | "confidential" | "restricted";
    locations: string[];
  }> = [];
  if (enrichedContext?.enrichment?.dataClassifications) {
    for (const dc of enrichedContext.enrichment.dataClassifications) {
      sensitiveDataTags.push({
        dataType: dc.dataType,
        sensitivity: dc.sensitivity,
        locations: dc.locations ?? [],
      });
    }
  }

  // ── Architecture ──
  const entryPoints: Array<{ kind: string; path: string; method?: string; description?: string }> =
    [];
  if (appModel?.routes) {
    for (const r of appModel.routes) {
      entryPoints.push({
        kind: r.framework ?? "HTTP",
        path: r.path,
        method: r.method,
        description: `${r.filePath}:${r.startLine}`,
      });
    }
  }

  const externalDeps: Array<{
    name: string;
    kind: string;
    trustLevel: "trusted" | "semi-trusted" | "untrusted" | "unknown";
    description?: string;
  }> = [];
  if (appModel?.outboundClients) {
    for (const c of appModel.outboundClients) {
      externalDeps.push({
        name: c.targetHint ?? c.symbol ?? c.id,
        kind: c.kind,
        trustLevel: "unknown",
        description: c.protocol ?? undefined,
      });
    }
  }

  const dataFlows: Array<{
    from: string;
    to: string;
    dataClassification?: string;
    description?: string;
  }> = [];
  if (threatModel?.dfd?.flows) {
    for (const flow of threatModel.dfd.flows) {
      dataFlows.push({
        from: flow.sourceId,
        to: flow.targetId,
        dataClassification: flow.dataClassification ?? undefined,
        description: flow.description,
      });
    }
  }

  // ── Historical ──
  const suppressedFps: Array<{ fingerprint: string; ruleId: string; reason?: string }> = [];
  const confirmedTps: Array<{ fingerprint: string; ruleId: string; description?: string }> = [];
  if (historicalFindings) {
    const fpSeen = new Set<string>();
    const tpSeen = new Set<string>();
    for (const f of historicalFindings) {
      if (f.verdict === "fp" && !fpSeen.has(f.fingerprint)) {
        fpSeen.add(f.fingerprint);
        suppressedFps.push({ fingerprint: f.fingerprint, ruleId: f.ruleId });
      } else if (f.verdict === "tp" && !tpSeen.has(f.fingerprint)) {
        tpSeen.add(f.fingerprint);
        confirmedTps.push({ fingerprint: f.fingerprint, ruleId: f.ruleId });
      }
    }
  }

  return {
    version: CONTEXT_VERSION,
    trust: {
      deploymentModel: [],
      infrastructure: dedupe(infrastructure).map((v) => item(v)),
      externalDefenses: dedupe(defenses).map((v) => item(v)),
      confirmedMitigations: dedupe(mitigations).map((v) => item(v)),
    },
    scope: {
      highValuePaths: dedupe(highValuePaths).map((v) => item(v)),
      lowValuePaths: [],
      sensitiveDataTags: sensitiveDataTags.map((v) => item(v)),
    },
    architecture: {
      entryPoints: entryPoints.map((v) => item(v)),
      externalDeps: externalDeps.map((v) => item(v)),
      dataFlows: dataFlows.map((v) => item(v)),
    },
    historical: {
      suppressedFpFingerprints: suppressedFps.map((v) => item(v)),
      confirmedTpFingerprints: confirmedTps.map((v) => item(v)),
    },
    operatorReviewed: false,
    generatedAt: new Date().toISOString(),
  };
}

/** Create an empty context for manual population. */
export function generateDefaultContext(): OperatorScanContext {
  return generateOperatorContextFromOutputs({});
}

// ── Merge strategy ──

/**
 * Merge a freshly auto-generated context with a persisted one.
 * Preserves operator-reviewed items, adds new auto-detected items as "skipped".
 */
export function mergeOperatorContexts(
  persisted: OperatorScanContext,
  fresh: OperatorScanContext,
): OperatorScanContext {
  function mergeItems<T>(
    existing: OperatorContextItem<T>[],
    generated: OperatorContextItem<T>[],
    keyFn: (v: T) => string,
  ): OperatorContextItem<T>[] {
    const existingKeys = new Set(existing.map((i) => keyFn(i.value)));
    const merged = [...existing];
    for (const g of generated) {
      if (!existingKeys.has(keyFn(g.value))) {
        merged.push(g);
      }
    }
    return merged;
  }

  const strKey = (v: string) => v;
  const objKey = (v: unknown) => JSON.stringify(v);

  return {
    ...persisted,
    trust: {
      deploymentModel: mergeItems(
        persisted.trust.deploymentModel,
        fresh.trust.deploymentModel,
        strKey,
      ),
      infrastructure: mergeItems(
        persisted.trust.infrastructure,
        fresh.trust.infrastructure,
        strKey,
      ),
      externalDefenses: mergeItems(
        persisted.trust.externalDefenses,
        fresh.trust.externalDefenses,
        strKey,
      ),
      confirmedMitigations: mergeItems(
        persisted.trust.confirmedMitigations,
        fresh.trust.confirmedMitigations,
        strKey,
      ),
    },
    scope: {
      highValuePaths: mergeItems(
        persisted.scope.highValuePaths,
        fresh.scope.highValuePaths,
        strKey,
      ),
      lowValuePaths: mergeItems(persisted.scope.lowValuePaths, fresh.scope.lowValuePaths, strKey),
      sensitiveDataTags: mergeItems(
        persisted.scope.sensitiveDataTags,
        fresh.scope.sensitiveDataTags,
        objKey,
      ),
    },
    architecture: {
      entryPoints: mergeItems(
        persisted.architecture.entryPoints,
        fresh.architecture.entryPoints,
        objKey,
      ),
      externalDeps: mergeItems(
        persisted.architecture.externalDeps,
        fresh.architecture.externalDeps,
        objKey,
      ),
      dataFlows: mergeItems(persisted.architecture.dataFlows, fresh.architecture.dataFlows, objKey),
    },
    historical: {
      suppressedFpFingerprints: mergeItems(
        persisted.historical.suppressedFpFingerprints,
        fresh.historical.suppressedFpFingerprints,
        objKey,
      ),
      confirmedTpFingerprints: mergeItems(
        persisted.historical.confirmedTpFingerprints,
        fresh.historical.confirmedTpFingerprints,
        objKey,
      ),
    },
  };
}

// ── Prompt formatting ──

function isActive(item: OperatorContextItem<unknown>): boolean {
  return item.status === "accepted" || item.status === "edited" || item.status === "added";
}

function formatStringItems(items: OperatorContextItem[], label: string): string[] {
  const active = items.filter(isActive);
  if (active.length === 0) return [];
  return [`**${label}**: ${active.map((i) => i.value).join(", ")}`];
}

export function formatOperatorContextForPrompt(ctx: OperatorScanContext): string {
  if (!ctx.operatorReviewed) return "";

  const sections: string[] = [];

  // Trust
  const trustLines: string[] = [];
  trustLines.push(...formatStringItems(ctx.trust.deploymentModel, "Deployment"));
  trustLines.push(...formatStringItems(ctx.trust.infrastructure, "Infrastructure"));
  trustLines.push(...formatStringItems(ctx.trust.externalDefenses, "External defenses"));
  const activeMitigations = ctx.trust.confirmedMitigations.filter(isActive);
  if (activeMitigations.length > 0) {
    trustLines.push("**Confirmed mitigations**:");
    for (const m of activeMitigations) {
      trustLines.push(`- ${m.value}`);
    }
  }
  if (trustLines.length > 0) {
    sections.push(`### Trust Context\n${trustLines.join("\n")}`);
  }

  // Scope
  const scopeLines: string[] = [];
  const hvp = ctx.scope.highValuePaths.filter(isActive);
  if (hvp.length > 0) {
    scopeLines.push("**High-value paths** (prioritize findings here):");
    for (const p of hvp) scopeLines.push(`- ${p.value}`);
  }
  const lvp = ctx.scope.lowValuePaths.filter(isActive);
  if (lvp.length > 0) {
    scopeLines.push("**Low-value paths** (lower priority):");
    for (const p of lvp) scopeLines.push(`- ${p.value}`);
  }
  const sdt = ctx.scope.sensitiveDataTags.filter(isActive);
  if (sdt.length > 0) {
    scopeLines.push("**Sensitive data**:");
    for (const t of sdt) {
      const locs = t.value.locations.join(", ");
      scopeLines.push(`- ${t.value.sensitivity}/${t.value.dataType}: ${locs}`);
    }
  }
  if (scopeLines.length > 0) {
    sections.push(`### Scope Prioritization\n${scopeLines.join("\n")}`);
  }

  // Architecture
  const archLines: string[] = [];
  const eps = ctx.architecture.entryPoints.filter(isActive);
  if (eps.length > 0) {
    archLines.push(`**Entry points**: ${eps.length} active`);
    for (const ep of eps.slice(0, 10)) {
      const desc = ep.value.description ? ` — ${ep.value.description}` : "";
      archLines.push(`- ${ep.value.method ?? ""} ${ep.value.path} (${ep.value.kind})${desc}`);
    }
    if (eps.length > 10) archLines.push(`- ...and ${eps.length - 10} more`);
  }
  const eds = ctx.architecture.externalDeps.filter(isActive);
  if (eds.length > 0) {
    archLines.push("**External dependencies**:");
    for (const d of eds) {
      archLines.push(`- ${d.value.name} (${d.value.kind}, ${d.value.trustLevel})`);
    }
  }
  const dfs = ctx.architecture.dataFlows.filter(isActive);
  if (dfs.length > 0) {
    archLines.push(`**Data flows**: ${dfs.length} cross-boundary flows identified`);
    for (const f of dfs.slice(0, 8)) {
      const cls = f.value.dataClassification ? ` [${f.value.dataClassification}]` : "";
      archLines.push(`- ${f.value.from} -> ${f.value.to}${cls}`);
    }
    if (dfs.length > 8) archLines.push(`- ...and ${dfs.length - 8} more`);
  }
  if (archLines.length > 0) {
    sections.push(`### Architecture\n${archLines.join("\n")}`);
  }

  // Historical
  const histLines: string[] = [];
  const fps = ctx.historical.suppressedFpFingerprints.filter(isActive);
  if (fps.length > 0) {
    histLines.push(
      `**Known false positives** (${fps.length} from prior scans — give these patterns FP benefit of the doubt):`,
    );
    for (const fp of fps.slice(0, 10)) {
      const reason = fp.value.reason ? ` (${fp.value.reason})` : "";
      histLines.push(`- ${fp.value.ruleId}${reason}`);
    }
    if (fps.length > 10) histLines.push(`- ...and ${fps.length - 10} more`);
  }
  const tps = ctx.historical.confirmedTpFingerprints.filter(isActive);
  if (tps.length > 0) {
    histLines.push(
      `**Confirmed true positives** (${tps.length} — patterns like these are likely real):`,
    );
    for (const tp of tps.slice(0, 10)) {
      histLines.push(`- ${tp.value.ruleId}`);
    }
    if (tps.length > 10) histLines.push(`- ...and ${tps.length - 10} more`);
  }
  if (histLines.length > 0) {
    sections.push(`### Historical Feedback\n${histLines.join("\n")}`);
  }

  if (sections.length === 0) return "";

  const header = [
    "## Operator-Provided Application Context",
    "",
    "The following context was provided by the operator and should override code-inferred assumptions.",
    "",
  ];

  const footer = [
    "",
    "Use this to:",
    "1. Adjust severity — findings in high-value paths are more critical.",
    "2. Validate controls — if operator confirms a mitigation, verify it actually applies to this finding before calling it a FP.",
    "3. Prioritize — focus investigation on high-value paths and untrusted dependencies.",
    "4. Skip confirmed FPs — the listed fingerprints have been operator-confirmed as false positives.",
  ];

  return [...header, ...sections, ...footer].join("\n");
}

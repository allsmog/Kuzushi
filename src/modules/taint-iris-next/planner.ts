import { existsSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import type { ThreatModelDocument } from "../../agents/tasks/threat-modeling/types.js";
import { resolveRepo } from "../../cli/shared.js";
import { coerceRepoContext } from "../../repo-context.js";
import { loadPersistentThreatModel } from "../../threat-model-renderer.js";
import type { RepoContext } from "../../types.js";
import { isRecord } from "../../utils.js";
import { contextSnapshotPath, loadContextSnapshot } from "../sast/context-persist.js";
import type { ExecutionContext } from "../types.js";
import {
  buildStructuralQueriesFromCatalog,
  filterCatalogForContext,
  rankCatalogEntries,
  renderCatalogForPrompt,
} from "./cwe-reference.js";
import type {
  TaintIrisNextArtifactStatus,
  TaintIrisNextBackend,
  TaintIrisNextBackendChoice,
  TaintIrisNextCaps,
  TaintIrisNextInput,
  TaintIrisNextMode,
  TaintIrisNextPlan,
} from "./types.js";

export const DEFAULT_TAINT_IRIS_NEXT_CAPS: TaintIrisNextCaps = {
  maxCatalogEntries: 24,
  maxCandidatesPerCwe: 24,
  maxEvidencePerCwe: 12,
  maxFilesPerQuery: 25,
  maxSpecsPerCwe: 16,
  maxAgentFindings: 20,
  codeqlAnalyzeTimeoutMs: 180_000,
  minEvidenceLevel: "linked",
};

const CODEQL_DB_CANDIDATES = [
  [".kuzushi", "codeql-db"],
  [".codeql", "db"],
] as const;

const LANGUAGE_BY_EXTENSION = new Map<string, string>([
  [".c", "c"],
  [".cc", "cpp"],
  [".cpp", "cpp"],
  [".cs", "csharp"],
  [".go", "go"],
  [".h", "c"],
  [".hpp", "cpp"],
  [".java", "java"],
  [".js", "javascript"],
  [".jsx", "javascript"],
  [".php", "php"],
  [".py", "python"],
  [".rb", "ruby"],
  [".rs", "rust"],
  [".ts", "typescript"],
  [".tsx", "typescript"],
]);

const INVENTORY_IGNORE_DIRS = new Set([
  ".git",
  ".kuzushi",
  ".next",
  ".turbo",
  "__pycache__",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "target",
  "vendor",
]);

export function buildTaintIrisNextPlan(
  input: TaintIrisNextInput,
  ctx: ExecutionContext,
): TaintIrisNextPlan {
  const mode = readMode(input.mode);
  const target = resolveTarget(input, ctx);
  const scanRoot = target;
  const repoRoot = resolveRepoRoot(target, ctx);
  const repoContextResolution = resolveRepoContext(ctx, scanRoot, repoRoot);
  const repoContext = repoContextResolution.repoContext;
  const threatModelResolution = resolveThreatModel(ctx, repoRoot, scanRoot);
  const threatModel = threatModelResolution.threatModel;
  const languages = collectLanguages(repoContext, input.languages ?? [], scanRoot);
  const effectiveCaps = adjustCapsForSparseLargeRepo(
    readCaps(input),
    repoContext,
    languages,
    scanRoot,
  );
  const filtered = filterCatalogForContext(repoContext, threatModel, languages);
  const catalog = rankCatalogEntries(filtered, {
    ...(repoContext ? { context: repoContext } : {}),
    ...(threatModel ? { threatModel } : {}),
    languages,
  }).slice(0, effectiveCaps.maxCatalogEntries);
  const structuralQueries = buildStructuralQueriesFromCatalog(catalog);
  const promptCatalog = renderCatalogForPrompt(catalog);
  const backend = chooseBackend(input.backend ?? "auto", repoRoot);
  const maxBudgetUsd = readPositiveNumber(input.maxBudgetUsd);

  return {
    target,
    scanRoot,
    repoRoot,
    mode,
    caps: effectiveCaps,
    languages,
    contextStatus: repoContextResolution.status,
    threatModelStatus: threatModelResolution.status,
    ...(repoContext ? { repoContext } : {}),
    ...(threatModel ? { threatModel } : {}),
    catalog,
    structuralQueries,
    promptCatalog,
    backend,
    ...(maxBudgetUsd !== undefined ? { maxBudgetUsd } : {}),
  };
}

export function hasRequiredContext(plan: TaintIrisNextPlan): boolean {
  return plan.contextStatus.ok || plan.languages.length > 0;
}

export function renderMissingContextGate(plan: TaintIrisNextPlan): string {
  return [
    "Taint IRIS Next needs usable Kuzushi context or a source-file inventory before it hunts.",
    `context: ${formatArtifactStatus(plan.contextStatus)}`,
    `file inventory languages: ${plan.languages.join(", ") || "none detected"}`,
    `threat model: ${formatArtifactStatus(plan.threatModelStatus)} (warning only)`,
    "",
    "Run /context, then rerun taint-iris-next. /threats regen dfd improves ranking but is no longer a hard blocker.",
  ].join("\n");
}

export function resolveTaintIrisNextPersistentArtifacts(target: string): {
  repoRoot: string;
  contextStatus: TaintIrisNextArtifactStatus;
  threatModelStatus: TaintIrisNextArtifactStatus;
} {
  const resolvedTarget = path.resolve(target);
  const repoRoot = resolveRepoRoot(resolvedTarget, {
    cwd: process.cwd(),
  } as ExecutionContext);
  const context = resolveContextFromDisk(resolvedTarget, repoRoot);
  const threatModel = resolveThreatModelFromDisk(resolvedTarget, repoRoot);
  return {
    repoRoot,
    contextStatus: context.status,
    threatModelStatus: threatModel.status,
  };
}

export function chooseBackend(
  requested: TaintIrisNextBackend,
  repoRoot: string,
): TaintIrisNextBackendChoice {
  const codeqlDbPath = detectExistingCodeqlDb(repoRoot);
  const warnings: string[] = [];
  const structuralTool = detectAstGrepAvailable() ? "ast-grep" : "rg";

  if (requested === "auto") {
    return {
      requested,
      selected: "structural",
      ...(codeqlDbPath ? { codeqlDbPath } : {}),
      ...(codeqlDbPath ? { corroborateWithCodeql: true } : {}),
      structuralTool,
      warnings,
    };
  }

  if (requested === "codeql") {
    if (codeqlDbPath) {
      return {
        requested,
        selected: "codeql",
        codeqlDbPath,
        corroborateWithCodeql: true,
        structuralTool,
        warnings,
      };
    }
    warnings.push(
      "backend=codeql requested, but no existing CodeQL DB was found; using structural evidence",
    );
    return {
      requested,
      selected: "structural",
      structuralTool,
      warnings,
    };
  }

  if (requested === "semgrep" || requested === "joern" || requested === "language") {
    warnings.push(`${requested} adapter is not implemented in V1; using structural evidence`);
    return {
      requested,
      selected: "structural",
      ...(codeqlDbPath ? { codeqlDbPath } : {}),
      structuralTool,
      warnings,
    };
  }

  return {
    requested,
    selected: "structural",
    ...(codeqlDbPath ? { codeqlDbPath } : {}),
    structuralTool,
    warnings,
  };
}

export function detectExistingCodeqlDb(repoRoot: string): string | undefined {
  for (const parts of CODEQL_DB_CANDIDATES) {
    const candidate = path.join(repoRoot, ...parts);
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

function adjustCapsForSparseLargeRepo(
  caps: TaintIrisNextCaps,
  repoContext: RepoContext | undefined,
  languages: readonly string[],
  scanRoot: string,
): TaintIrisNextCaps {
  const sparse =
    !repoContext ||
    repoContext.frameworks.length + repoContext.ormOrDb.length + repoContext.entryPoints.length < 2;
  if (!sparse || !languages.includes("python")) return caps;
  const fileEstimate = estimateFileCount(scanRoot, 600);
  if (fileEstimate < 250) return caps;
  return {
    ...caps,
    maxCatalogEntries: Math.max(caps.maxCatalogEntries, 12),
  };
}

function estimateFileCount(root: string, limit: number): number {
  const stack = [root];
  let count = 0;
  while (stack.length > 0 && count < limit) {
    const current = stack.pop();
    if (!current) continue;
    let stat: ReturnType<typeof statSync>;
    try {
      stat = statSync(current);
    } catch {
      continue;
    }
    if (stat.isFile()) {
      count += 1;
      continue;
    }
    if (!stat.isDirectory()) continue;
    let entries: string[];
    try {
      entries = readdirSync(current);
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (INVENTORY_IGNORE_DIRS.has(entry)) continue;
      stack.push(path.join(current, entry));
    }
  }
  return count;
}

function readMode(value: unknown): TaintIrisNextMode {
  return value === "hunt" ? "hunt" : "plan";
}

function readCaps(input: TaintIrisNextInput): TaintIrisNextCaps {
  return {
    maxCatalogEntries: readPositiveInt(
      input.maxCatalogEntries ?? input.maxCwes,
      DEFAULT_TAINT_IRIS_NEXT_CAPS.maxCatalogEntries,
    ),
    maxCandidatesPerCwe: readPositiveInt(
      input.maxCandidatesPerCwe,
      DEFAULT_TAINT_IRIS_NEXT_CAPS.maxCandidatesPerCwe,
    ),
    maxEvidencePerCwe: readPositiveInt(
      input.maxEvidencePerCwe,
      DEFAULT_TAINT_IRIS_NEXT_CAPS.maxEvidencePerCwe,
    ),
    maxFilesPerQuery: readPositiveInt(
      input.maxFilesPerQuery,
      DEFAULT_TAINT_IRIS_NEXT_CAPS.maxFilesPerQuery,
    ),
    maxSpecsPerCwe: readPositiveInt(
      input.maxSpecsPerCwe,
      DEFAULT_TAINT_IRIS_NEXT_CAPS.maxSpecsPerCwe,
    ),
    maxAgentFindings: readPositiveInt(
      input.maxAgentFindings,
      DEFAULT_TAINT_IRIS_NEXT_CAPS.maxAgentFindings,
    ),
    codeqlAnalyzeTimeoutMs: readBoundedPositiveInt(
      input.codeqlAnalyzeTimeoutMs,
      DEFAULT_TAINT_IRIS_NEXT_CAPS.codeqlAnalyzeTimeoutMs,
      30_000,
      900_000,
    ),
    minEvidenceLevel: readMinEvidenceLevel(input.minEvidenceLevel),
  };
}

function readPositiveInt(value: unknown, fallback: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 1) return fallback;
  return Math.floor(numeric);
}

function readBoundedPositiveInt(
  value: unknown,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 1) return fallback;
  return Math.min(maximum, Math.max(minimum, Math.floor(numeric)));
}

function readMinEvidenceLevel(value: unknown): TaintIrisNextCaps["minEvidenceLevel"] {
  return value === "path" || value === "linked" || value === "candidate" ? value : "linked";
}

function readPositiveNumber(value: unknown): number | undefined {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return undefined;
  return numeric;
}

function resolveTarget(input: TaintIrisNextInput, ctx: ExecutionContext): string {
  const raw = input.target ?? ctx.target ?? ctx.cwd;
  return path.resolve(ctx.cwd, raw);
}

function resolveRepoRoot(target: string, ctx: ExecutionContext): string {
  if (ctx.dag?.repoRoot) return ctx.dag.repoRoot;
  const repo = resolveRepo(target);
  if (repo.gitRoot) return repo.gitRoot;
  try {
    const stat = statSync(target);
    return stat.isDirectory() ? target : ctx.cwd;
  } catch {
    return ctx.cwd;
  }
}

function resolveRepoContext(
  ctx: ExecutionContext,
  scanRoot: string,
  repoRoot: string,
): { repoContext?: RepoContext; status: TaintIrisNextArtifactStatus } {
  let emptySeeded = false;
  for (const raw of readSeededOutputs(ctx, ["context-gatherer", "context:context-gatherer"])) {
    const context = coerceRepoContext(raw);
    if (context && isUsefulRepoContext(context)) {
      return {
        repoContext: context,
        status: { ok: true, reason: "loaded from upstream context task" },
      };
    }
    if (context) emptySeeded = true;
  }
  const disk = resolveContextFromDisk(scanRoot, repoRoot);
  if (disk.repoContext) return disk;
  if (emptySeeded) {
    return {
      status: {
        ok: false,
        reason:
          "upstream context task was present but did not include languages, frameworks, DB/ORM, or entry points",
      },
    };
  }
  return disk;
}

function resolveThreatModel(
  ctx: ExecutionContext,
  repoRoot: string,
  scanRoot: string,
): { threatModel?: ThreatModelDocument; status: TaintIrisNextArtifactStatus } {
  let emptySeeded = false;
  for (const raw of readSeededOutputs(ctx, [
    "threat-model-randori",
    "threat-model:threat-model-randori",
  ])) {
    const document = coerceThreatModelDocument(raw);
    if (document && isUsefulThreatModel(document)) {
      return {
        threatModel: document,
        status: { ok: true, reason: "loaded from upstream threat-model task" },
      };
    }
    if (document) emptySeeded = true;
  }
  const disk = resolveThreatModelFromDisk(scanRoot, repoRoot);
  if (disk.threatModel) return disk;
  if (emptySeeded) {
    return {
      status: {
        ok: false,
        reason:
          "upstream threat model was present but had no threats, DFD elements, trust boundaries, or narrative",
      },
    };
  }
  return disk;
}

function resolveContextFromDisk(
  scanRoot: string,
  repoRoot: string,
): { repoContext?: RepoContext; status: TaintIrisNextArtifactStatus } {
  let emptyPath: string | undefined;
  for (const root of candidateArtifactRoots(scanRoot, repoRoot)) {
    const snapshotPath = contextSnapshotPath(root);
    const snapshot = loadContextSnapshot(root);
    if (!snapshot) continue;
    const context = coerceRepoContext(snapshot);
    if (
      (context && isUsefulRepoContext(context)) ||
      snapshotHasUsefulApplicationContext(snapshot)
    ) {
      return {
        ...(context ? { repoContext: context } : {}),
        status: { ok: true, path: snapshotPath, reason: "loaded usable context snapshot" },
      };
    }
    emptyPath = snapshotPath;
  }
  if (emptyPath) {
    return {
      status: {
        ok: false,
        path: emptyPath,
        reason: "context snapshot exists but lacks languages, frameworks, DB/ORM, and entry points",
      },
    };
  }
  return { status: { ok: false, reason: "no context snapshot found" } };
}

function resolveThreatModelFromDisk(
  scanRoot: string,
  repoRoot: string,
): { threatModel?: ThreatModelDocument; status: TaintIrisNextArtifactStatus } {
  let emptyPath: string | undefined;
  for (const root of candidateArtifactRoots(scanRoot, repoRoot)) {
    const model = loadPersistentThreatModel(root);
    const modelPath = path.join(root, ".kuzushi", "threat-model.json");
    if (!model) continue;
    if (isUsefulThreatModel(model)) {
      return {
        threatModel: model,
        status: { ok: true, path: modelPath, reason: "loaded usable threat model" },
      };
    }
    emptyPath = modelPath;
  }
  if (emptyPath) {
    return {
      status: {
        ok: false,
        path: emptyPath,
        reason:
          "threat model exists but has no threats, DFD elements, trust boundaries, or narrative",
      },
    };
  }
  return { status: { ok: false, reason: "no threat model found" } };
}

function candidateArtifactRoots(scanRoot: string, repoRoot: string): string[] {
  const roots: string[] = [];
  const seen = new Set<string>();
  const add = (root: string): void => {
    const resolved = path.resolve(root);
    if (seen.has(resolved)) return;
    seen.add(resolved);
    roots.push(resolved);
  };
  add(scanRoot);
  add(repoRoot);

  let current = path.resolve(scanRoot);
  const stop = path.parse(current).root;
  while (current !== stop) {
    current = path.dirname(current);
    add(current);
    if (current === path.resolve(repoRoot)) break;
  }
  return roots;
}

function isUsefulRepoContext(context: RepoContext): boolean {
  return (
    context.languages.length > 0 ||
    context.frameworks.length > 0 ||
    context.authPatterns.length > 0 ||
    context.sanitizationLibs.length > 0 ||
    context.ormOrDb.length > 0 ||
    context.entryPoints.length > 0
  );
}

function snapshotHasUsefulApplicationContext(snapshot: unknown): boolean {
  if (!isRecord(snapshot)) return false;
  const appModel = snapshot["appModel"];
  if (isRecord(appModel)) {
    const usefulArrayFields = [
      "routes",
      "outboundClients",
      "dataStores",
      "backgroundJobs",
      "serviceBoundaries",
      "relevantFiles",
    ];
    if (
      usefulArrayFields.some((field) => {
        const value = appModel[field];
        return Array.isArray(value) && value.length > 0;
      })
    ) {
      return true;
    }
  }

  const fileIndex = snapshot["fileIndex"];
  if (isRecord(fileIndex)) {
    const totalFiles = Number(fileIndex["totalFiles"]);
    if (Number.isFinite(totalFiles) && totalFiles > 0) return true;
    const patternMatches = fileIndex["patternMatches"];
    if (isRecord(patternMatches) && Object.keys(patternMatches).length > 0) return true;
  }

  return false;
}

function isUsefulThreatModel(document: ThreatModelDocument): boolean {
  const dfd = document.dfd as unknown as {
    nodes?: unknown[];
    elements?: unknown[];
    flows?: unknown[];
    trustBoundaries?: unknown[];
  };
  const narrative = (
    document as unknown as { narrative?: { overview?: string; attackerStories?: unknown[] } }
  ).narrative;
  return (
    document.threats.length > 0 ||
    (dfd.nodes?.length ?? 0) > 0 ||
    (dfd.elements?.length ?? 0) > 0 ||
    (dfd.flows?.length ?? 0) > 0 ||
    (dfd.trustBoundaries?.length ?? 0) > 0 ||
    !!narrative?.overview?.trim() ||
    (narrative?.attackerStories?.length ?? 0) > 0
  );
}

function formatArtifactStatus(status: TaintIrisNextArtifactStatus): string {
  const prefix = status.ok ? "loaded" : "missing/incomplete";
  return status.path
    ? `${prefix} (${status.path}; ${status.reason})`
    : `${prefix} (${status.reason})`;
}

function detectAstGrepAvailable(): boolean {
  return (
    resolveExecutableFromPath("ast-grep") !== undefined ||
    resolveExecutableFromPath("sg") !== undefined
  );
}

function resolveExecutableFromPath(command: string): string | undefined {
  const pathValue = process.env.PATH ?? "";
  for (const dir of pathValue.split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, command);
    try {
      const stat = statSync(candidate);
      if (stat.isFile()) return candidate;
    } catch {
      // Continue scanning PATH.
    }
  }
  return undefined;
}

function readSeededOutputs(ctx: ExecutionContext, keys: readonly string[]): unknown[] {
  const maps = [ctx.seedTaskOutputs, ctx.dag?.upstreamOutputs].filter(
    (map): map is ReadonlyMap<string, unknown> => !!map,
  );
  const values: unknown[] = [];
  for (const map of maps) {
    for (const key of keys) {
      if (map.has(key)) values.push(map.get(key));
    }
  }
  return values;
}

function coerceThreatModelDocument(raw: unknown): ThreatModelDocument | undefined {
  if (!isRecord(raw)) return undefined;
  const candidate = isRecord(raw["document"]) ? raw["document"] : raw;
  if (!isRecord(candidate) || !Array.isArray(candidate["threats"]) || !isRecord(candidate["dfd"])) {
    return undefined;
  }
  return candidate as unknown as ThreatModelDocument;
}

function collectLanguages(
  repoContext: RepoContext | undefined,
  explicit: readonly string[],
  scanRoot: string,
): string[] {
  const languages = new Set<string>();
  for (const language of repoContext?.languages ?? []) addLanguage(languages, language);
  for (const language of explicit) addLanguage(languages, language);
  if (languages.size === 0) {
    for (const language of detectLanguagesFromFiles(scanRoot)) addLanguage(languages, language);
  }
  return [...languages].sort();
}

function addLanguage(target: Set<string>, language: string): void {
  const normalized = language.trim().toLowerCase();
  if (normalized) target.add(normalized);
}

function detectLanguagesFromFiles(root: string): string[] {
  const languages = new Set<string>();
  const stack = [root];
  let visited = 0;

  while (stack.length > 0 && visited < 2000) {
    const current = stack.pop();
    if (!current) continue;
    let stat: ReturnType<typeof statSync>;
    try {
      stat = statSync(current);
    } catch {
      continue;
    }
    if (stat.isFile()) {
      visited += 1;
      const language = LANGUAGE_BY_EXTENSION.get(path.extname(current).toLowerCase());
      if (language) languages.add(language);
      continue;
    }
    if (!stat.isDirectory()) continue;
    let entries: string[];
    try {
      entries = readdirSync(current);
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (INVENTORY_IGNORE_DIRS.has(entry)) continue;
      stack.push(path.join(current, entry));
    }
  }

  return [...languages];
}

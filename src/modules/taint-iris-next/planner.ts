import { existsSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import type { ThreatModelDocument } from "../../agents/tasks/threat-modeling/types.js";
import { resolveRepo } from "../../cli/shared.js";
import { coerceRepoContext } from "../../repo-context.js";
import { loadPersistentThreatModel } from "../../threat-model-renderer.js";
import type { RepoContext } from "../../types.js";
import { isRecord } from "../../utils.js";
import { loadContextSnapshot } from "../sast/context-persist.js";
import type { ExecutionContext } from "../types.js";
import {
  buildStructuralQueriesFromCatalog,
  filterCatalogForContext,
  rankCatalogEntries,
  renderCatalogForPrompt,
} from "./cwe-reference.js";
import type {
  TaintIrisNextBackend,
  TaintIrisNextBackendChoice,
  TaintIrisNextCaps,
  TaintIrisNextInput,
  TaintIrisNextMode,
  TaintIrisNextPlan,
} from "./types.js";

export const DEFAULT_TAINT_IRIS_NEXT_CAPS: TaintIrisNextCaps = {
  maxCatalogEntries: 24,
  maxEvidencePerCwe: 12,
  maxFilesPerQuery: 25,
  maxAgentFindings: 20,
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
  const caps = readCaps(input);
  const target = resolveTarget(input, ctx);
  const scanRoot = target;
  const repoRoot = resolveRepoRoot(target, ctx);
  const repoContext = resolveRepoContext(ctx, scanRoot);
  const threatModel = resolveThreatModel(ctx, repoRoot, scanRoot);
  const languages = collectLanguages(repoContext, input.languages ?? [], scanRoot);
  const filtered = filterCatalogForContext(repoContext, threatModel, languages);
  const catalog = rankCatalogEntries(filtered, {
    ...(repoContext ? { context: repoContext } : {}),
    ...(threatModel ? { threatModel } : {}),
    languages,
  }).slice(0, caps.maxCatalogEntries);
  const structuralQueries = buildStructuralQueriesFromCatalog(catalog);
  const promptCatalog = renderCatalogForPrompt(catalog);
  const backend = chooseBackend(input.backend ?? "auto", repoRoot);
  const maxBudgetUsd = readPositiveNumber(input.maxBudgetUsd);

  return {
    target,
    scanRoot,
    repoRoot,
    mode,
    caps,
    languages,
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
  return !!plan.repoContext && !!plan.threatModel;
}

export function renderMissingContextGate(plan: TaintIrisNextPlan): string {
  const missing = [
    plan.repoContext ? "" : "context",
    plan.threatModel ? "" : "threat model",
  ].filter(Boolean);
  return [
    "Taint IRIS Next needs Kuzushi context and a threat model before it hunts.",
    `missing: ${missing.join(" and ")}`,
    "",
    "Run /context, then /threats regen dfd, then rerun taint-iris-next.",
  ].join("\n");
}

export function chooseBackend(
  requested: TaintIrisNextBackend,
  repoRoot: string,
): TaintIrisNextBackendChoice {
  const codeqlDbPath = detectExistingCodeqlDb(repoRoot);
  const warnings: string[] = [];
  const structuralTool = "rg";

  if (requested === "auto") {
    return {
      requested,
      selected: codeqlDbPath ? "codeql" : "structural",
      ...(codeqlDbPath ? { codeqlDbPath } : {}),
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

function readMode(value: unknown): TaintIrisNextMode {
  return value === "hunt" ? "hunt" : "plan";
}

function readCaps(input: TaintIrisNextInput): TaintIrisNextCaps {
  return {
    maxCatalogEntries: readPositiveInt(
      input.maxCatalogEntries ?? input.maxCwes,
      DEFAULT_TAINT_IRIS_NEXT_CAPS.maxCatalogEntries,
    ),
    maxEvidencePerCwe: readPositiveInt(
      input.maxEvidencePerCwe,
      DEFAULT_TAINT_IRIS_NEXT_CAPS.maxEvidencePerCwe,
    ),
    maxFilesPerQuery: readPositiveInt(
      input.maxFilesPerQuery,
      DEFAULT_TAINT_IRIS_NEXT_CAPS.maxFilesPerQuery,
    ),
    maxAgentFindings: readPositiveInt(
      input.maxAgentFindings,
      DEFAULT_TAINT_IRIS_NEXT_CAPS.maxAgentFindings,
    ),
  };
}

function readPositiveInt(value: unknown, fallback: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 1) return fallback;
  return Math.floor(numeric);
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

function resolveRepoContext(ctx: ExecutionContext, scanRoot: string): RepoContext | undefined {
  for (const raw of readSeededOutputs(ctx, ["context-gatherer", "context:context-gatherer"])) {
    const context = coerceRepoContext(raw);
    if (context) return context;
  }
  const snapshot = loadContextSnapshot(scanRoot);
  const context = coerceRepoContext(snapshot);
  if (context) return context;
  return undefined;
}

function resolveThreatModel(
  ctx: ExecutionContext,
  repoRoot: string,
  scanRoot: string,
): ThreatModelDocument | undefined {
  for (const raw of readSeededOutputs(ctx, [
    "threat-model-randori",
    "threat-model:threat-model-randori",
  ])) {
    const document = coerceThreatModelDocument(raw);
    if (document) return document;
  }
  const fromScanRoot = loadPersistentThreatModel(scanRoot);
  if (fromScanRoot) return fromScanRoot;
  const fromRepoRoot = loadPersistentThreatModel(repoRoot);
  if (fromRepoRoot) return fromRepoRoot;
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

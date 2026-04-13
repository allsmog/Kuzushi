import { existsSync } from "node:fs";
import path from "node:path";
import type { FileIndex, KuzushiConfig } from "../../../types.js";
import { resolveScannerConfig } from "../../../capabilities.js";
import type { TaskContext } from "../../types.js";
import { isPathWithinRoot } from "../../../utils.js";

export const SYSTEMS_PATTERN_DOMAINS = [
  "protocol-parser",
  "integer-boundary",
  "unsafe-memory",
  "hardening",
] as const;

export type SystemsPatternDomain = (typeof SYSTEMS_PATTERN_DOMAINS)[number];

export const SYSTEMS_HUNT_LENSES = [
  "protocol-state",
  "arithmetic-sentinel",
  "buffer-unsafe",
  "hardening-bypass",
] as const;

export type SystemsHuntLens = (typeof SYSTEMS_HUNT_LENSES)[number];

export type SystemsSurfaceKind =
  | "protocol-parser"
  | "rpc-handler"
  | "codec-parser"
  | "hypervisor-boundary"
  | "unsafe-region"
  | "buffer-operation"
  | "boundary-heavy-routine";

export type SystemsInvariantKind =
  | "state-transition"
  | "packet-ordering"
  | "sentinel-boundary"
  | "counter-upper-bound"
  | "length-buffer-coupling"
  | "unsafe-precondition";

export type SystemsHelperTemplateId =
  | "signed-wraparound"
  | "counter-allocation-flow"
  | "stack-length-copy"
  | "rpc-xdr-length"
  | "rust-unsafe-len"
  | "hardening-presence";

export type SystemsCorroborationStatus =
  | "survived"
  | "counterexample-found"
  | "lens-agreement-only"
  | "insufficient-corroboration";

export interface SystemsSurfaceSignal {
  domain: SystemsPatternDomain;
  lineNumber: number;
  lineContent: string;
  reason: string;
}

export interface RankedSystemsSurface {
  id: string;
  filePath: string;
  startLine: number;
  displayName: string;
  kind: SystemsSurfaceKind;
  score: number;
  domains: SystemsPatternDomain[];
  reasons: string[];
  attackerControlledFields: string[];
  hardeningSignals: string[];
  evidence: SystemsSurfaceSignal[];
}

export interface SystemsCodeLocation {
  filePath: string;
  line: number;
  snippet: string;
  reason?: string;
  symbol?: string;
}

export interface SystemsHelperTemplate {
  id: SystemsHelperTemplateId;
  title: string;
  rationale: string;
  queryText?: string;
}

export interface SystemsSurfacePack {
  surfaceId: string;
  anchorFilePath: string;
  anchorStartLine: number;
  anchorSymbol?: string;
  relatedFiles: string[];
  callers: SystemsCodeLocation[];
  callees: SystemsCodeLocation[];
  compareCastSites: SystemsCodeLocation[];
  counterSites: SystemsCodeLocation[];
  sentinelConstants: SystemsCodeLocation[];
  allocationCopySites: SystemsCodeLocation[];
  unsafeSites: SystemsCodeLocation[];
  inputSites: SystemsCodeLocation[];
  hardeningSites: SystemsCodeLocation[];
  helperTemplates: SystemsHelperTemplate[];
}

export interface SystemsContextOutput {
  surfaces: RankedSystemsSurface[];
  surfacePacks: SystemsSurfacePack[];
  metadata: {
    codeqlAvailable: boolean;
    codeqlDbPath?: string;
    bashProbingUsed: boolean;
  };
}

export interface SystemsInvariant {
  id: string;
  surfaceId: string;
  kind: SystemsInvariantKind;
  summary: string;
  statement: string;
  rationale: string;
  evidence: string[];
  attackerControlledFields: string[];
  cheapVerifiable: boolean;
}

export interface SystemsInvariantOutput {
  invariants: SystemsInvariant[];
}

export interface SystemsTriggerHypothesis {
  id: string;
  surfaceId: string;
  orderedSteps: string[];
  boundaryAssignments: Record<string, string>;
  statePreconditions: string[];
  attackerControlledFields: string[];
  expectedPrimitive: string;
  cheapVerifiable: boolean;
  rationale: string;
}

export interface SystemsTriggerOutput {
  triggers: SystemsTriggerHypothesis[];
}

export interface SystemsAnalysisStep {
  filePath: string;
  line: number;
  role: string;
  snippet?: string;
}

export interface SystemsHuntArtifact {
  fingerprint: string;
  title: string;
  cwe: string[];
  severity: string;
  filePath: string;
  startLine: number;
  surfaceId: string;
  surfaceKind: SystemsSurfaceKind;
  lenses: SystemsHuntLens[];
  violatedInvariantIds: string[];
  violatedInvariant: string;
  triggerHypothesisIds: string[];
  triggerSequence: string[];
  stateMachine: string[];
  boundaryAssignments: Record<string, string>;
  attackerControlledFields: string[];
  memoryPrimitive: string;
  hardeningNotes: string[];
  cheapVerifiable: boolean;
  reasoning: string;
  analysisPath: SystemsAnalysisStep[];
  guardLocations: SystemsAnalysisStep[];
  counterexampleNotes: string[];
  relatedFiles: string[];
  corroborationStatus: SystemsCorroborationStatus;
}

export interface SystemsHuntConfig {
  model: string;
  maxFindings: number;
  maxSurfaces: number;
  surfacePackDepth: number;
  maxTriggerHypothesesPerSurface: number;
  maxConcurrentSurfaces: number;
  maxTurnsPerSurface: number;
  minLensAgreement: number;
  maxCorroborationTurns: number;
  artifactRoot: string;
  artifactRootRelative: string;
  enableCodeqlAssist: boolean;
  enableBashProbing: boolean;
  enableCodeqlTemplates: boolean;
  enableCounterexamplePass: boolean;
}

export function isSystemsLanguage(language: string): boolean {
  const normalized = language.trim().toLowerCase();
  return normalized === "c" || normalized === "c++" || normalized === "cpp" || normalized === "rust";
}

export function hasSystemsSignals(fileIndex: FileIndex | undefined): boolean {
  if (!fileIndex) return false;
  return SYSTEMS_PATTERN_DOMAINS.some((domain) => (fileIndex.patternMatches[domain]?.length ?? 0) > 0);
}

export function resolveSystemsHuntConfig(
  context: Pick<TaskContext, "config" | "repoRoot" | "modelOverride">,
): SystemsHuntConfig {
  const raw = resolveScannerConfig(context.config as KuzushiConfig, "systems-hunt");
  const configuredModel = asNonEmptyString(raw["model"]);
  const artifactRootRelative = normalizeArtifactDir(asNonEmptyString(raw["artifactDir"]) || ".kuzushi/systems-hunt");
  const artifactRoot = path.resolve(context.repoRoot, artifactRootRelative);

  if (!isPathWithinRoot(context.repoRoot, artifactRoot)) {
    throw new Error(`systems-hunt artifactDir must stay inside the repository root: ${artifactRootRelative}`);
  }

  return {
    model: context.modelOverride ?? configuredModel ?? context.config.model,
    maxFindings: asPositiveInt(raw["maxFindings"], 30),
    maxSurfaces: asPositiveInt(raw["maxSurfaces"], 10),
    surfacePackDepth: asPositiveInt(raw["surfacePackDepth"], 4),
    maxTriggerHypothesesPerSurface: asPositiveInt(raw["maxTriggerHypothesesPerSurface"], 3),
    maxConcurrentSurfaces: asPositiveInt(raw["maxConcurrentSurfaces"], 2),
    maxTurnsPerSurface: asPositiveInt(raw["maxTurnsPerSurface"], 16),
    minLensAgreement: Math.min(SYSTEMS_HUNT_LENSES.length, asPositiveInt(raw["minLensAgreement"], 2)),
    maxCorroborationTurns: asPositiveInt(raw["maxCorroborationTurns"], 8),
    artifactRoot,
    artifactRootRelative,
    enableCodeqlAssist: asBoolean(raw["enableCodeqlAssist"], true),
    enableBashProbing: asBoolean(raw["enableBashProbing"], true),
    enableCodeqlTemplates: asBoolean(raw["enableCodeqlTemplates"], true),
    enableCounterexamplePass: asBoolean(raw["enableCounterexamplePass"], true),
  };
}

export function resolveSystemsCodeqlDbPath(repoRoot: string): string | undefined {
  const candidates = [
    path.join(repoRoot, ".kuzushi", "codeql-db"),
    path.join(repoRoot, ".codeql", "db"),
  ];
  return candidates.find((candidate) => isPathWithinRoot(repoRoot, candidate) && exists(candidate));
}

function normalizeArtifactDir(raw: string): string {
  const normalized = raw.trim().replace(/\\/g, "/").replace(/^\/+/, "");
  return normalized || ".kuzushi/systems-hunt";
}

function asPositiveInt(value: unknown, fallback: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 1) return fallback;
  return Math.floor(numeric);
}

function asBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value === "true") return true;
    if (value === "false") return false;
  }
  return fallback;
}

function asNonEmptyString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function exists(candidate: string): boolean {
  return existsSync(candidate);
}

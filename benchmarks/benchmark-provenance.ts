import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { BENCHMARK_CONTRACT_FILES } from "./benchmark-contract-files.js";
import {
  assertExecutionMatchesDeclaration,
  executionEvidenceMatches,
} from "./benchmark-execution-evidence.js";
import { digestJson } from "./benchmark-json-digest.js";
import { parseScanConfig, parseScanConfigArgument } from "./benchmark-scan-config.js";
import type {
  BaselineMetrics,
  BenchmarkComparableProvenance,
  BenchmarkMetrics,
  BenchmarkProvenanceInput,
  BenchmarkResultProvenance,
  BenchmarkSpendReceipt,
  CweMetrics,
  GroundTruthDataset,
} from "./types.js";

const COMPARABLE_FIELDS = [
  "datasetName",
  "datasetDigest",
  "datasetRevision",
  "harnessContractVersion",
  "harnessDigest",
  "scanConfigDigest",
  "modelIdentity",
  "scoringMode",
] as const;
const COUNT_FIELDS = ["tp", "fp", "fn", "tn"] as const;
const PROBABILITY_FIELDS = ["precision", "recall", "f1"] as const;
const __dirname = dirname(fileURLToPath(import.meta.url));

interface ProvenanceBuildInput {
  declaration: BenchmarkProvenanceInput;
  dataset: GroundTruthDataset;
  durationMs: number;
  spend: BenchmarkSpendReceipt;
}

export function loadProvenanceInput(path: string): BenchmarkProvenanceInput {
  const resolved = resolve(path);
  const parsed: unknown = JSON.parse(readFileSync(resolved, "utf8"));
  if (!isProvenanceInput(parsed)) {
    throw new Error(`Malformed benchmark provenance input: ${resolved}`);
  }
  return {
    ...parsed,
    scanConfig: parseScanConfig(parsed.scanConfig, `${resolved} scanConfig`),
  };
}

export function buildResultProvenance(input: ProvenanceBuildInput): BenchmarkResultProvenance {
  const { declaration, dataset, durationMs, spend } = input;
  assertExecutionMatchesDeclaration(declaration, spend);
  return {
    schemaVersion: 1,
    mode: declaration.executionMode,
    comparable: {
      datasetName: dataset.name,
      datasetDigest: digestJson(dataset),
      datasetRevision: datasetRevision(dataset),
      harnessContractVersion: declaration.harnessContractVersion,
      harnessDigest: harnessDigest(),
      scanConfigDigest: digestJson(declaration.scanConfig),
      modelIdentity: declaration.modelIdentity,
      scoringMode: "strict-cwe-v1",
    },
    observed: {
      kuzushiRevision: declaration.kuzushiRevision,
      generatedAt: declaration.generatedAt,
      durationMs,
      runId: spend.runId,
      spendSource: spend.source,
      models: spend.models,
      llmCallCount: spend.llmCallCount,
      llmAuditComplete: spend.llmAuditComplete,
      ...(spend.configHash === undefined ? {} : { configHash: spend.configHash }),
    },
  };
}

export function assertConfigMatchesDeclaration(
  rawConfig: string | undefined,
  declaration: BenchmarkProvenanceInput,
): void {
  if (rawConfig === undefined) return;
  const parsed = parseScanConfigArgument(rawConfig);
  if (digestJson(parsed) !== digestJson(declaration.scanConfig)) {
    throw new Error("--config contradicts the scanConfig in --provenance");
  }
}

export function assertMetrics(value: unknown, source: string): asserts value is BenchmarkMetrics {
  if (!isBenchmarkMetrics(value)) throw new Error(`Malformed benchmark metrics: ${source}`);
}

export function assertBaseline(value: unknown, source: string): asserts value is BaselineMetrics {
  if (!isBaselineMetrics(value)) throw new Error(`Malformed benchmark baseline: ${source}`);
  assertCompatibleResultSet(Object.values(value.datasets), `baseline ${source}`);
}

export function assertCompatibleResults(before: BenchmarkMetrics, after: BenchmarkMetrics): void {
  const differences = provenanceDifferences(before, after);
  if (differences.length === 0) return;
  throw new Error(
    `Incomparable benchmark provenance for ${after.dataset}: ${differences.join("; ")}. ` +
      "Create an intentional new baseline instead of overwriting this one.",
  );
}

export function assertCompatibleResultSet(metrics: BenchmarkMetrics[], source: string): void {
  const names = new Set<string>();
  for (const result of metrics) {
    if (names.has(result.dataset))
      throw new Error(`Duplicate dataset ${result.dataset} in ${source}`);
    names.add(result.dataset);
  }
  const reference = metrics[0];
  for (const result of metrics.slice(1)) assertSharedProvenance(reference, result, source);
}

export function shortDigest(value: string): string {
  return value.slice(0, 12);
}

function isProvenanceInput(value: unknown): value is BenchmarkProvenanceInput {
  if (!isRecord(value) || value.schemaVersion !== 1 || !isRecord(value.scanConfig)) return false;
  if (value.executionMode !== "deterministic-fixture" && value.executionMode !== "real-model") {
    return false;
  }
  return (
    isNonemptyString(value.harnessContractVersion) &&
    isNonemptyString(value.modelIdentity) &&
    isNonemptyString(value.kuzushiRevision) &&
    isIsoTimestamp(value.generatedAt)
  );
}

function isBenchmarkMetrics(value: unknown): value is BenchmarkMetrics {
  if (!isRecord(value) || !isNonemptyString(value.dataset) || !isRecord(value.perCwe)) return false;
  if (!isResultProvenance(value.provenance, value.dataset)) return false;
  return (
    COUNT_FIELDS.every((key) => isNonnegativeInteger(value[key])) &&
    PROBABILITY_FIELDS.every((key) => isProbability(value[key])) &&
    isNonnegativeFinite(value.costUsd) &&
    isSpendReceipt(value.spend) &&
    isNonnegativeFinite(value.durationMs) &&
    value.durationMs === value.provenance.observed.durationMs &&
    value.spend.runId === value.provenance.observed.runId &&
    value.spend.source === value.provenance.observed.spendSource &&
    arraysEqual(value.spend.models, value.provenance.observed.models) &&
    value.spend.llmCallCount === value.provenance.observed.llmCallCount &&
    value.spend.llmAuditComplete === value.provenance.observed.llmAuditComplete &&
    value.spend.configHash === value.provenance.observed.configHash &&
    executionEvidenceMatches(
      value.provenance.mode,
      value.provenance.comparable.modelIdentity,
      value.spend,
    ) &&
    Object.values(value.perCwe).every(isCweMetrics)
  );
}

function isBaselineMetrics(value: unknown): value is BaselineMetrics {
  return (
    isRecord(value) &&
    value.schemaVersion === 2 &&
    isIsoTimestamp(value.updatedAt) &&
    isRecord(value.datasets) &&
    Object.values(value.datasets).every(isBenchmarkMetrics)
  );
}

function isResultProvenance(value: unknown, dataset: string): value is BenchmarkResultProvenance {
  if (!isRecord(value) || value.schemaVersion !== 1) return false;
  if (value.mode !== "deterministic-fixture" && value.mode !== "real-model") return false;
  if (!isComparable(value.comparable, dataset) || !isRecord(value.observed)) return false;
  return (
    isNonemptyString(value.observed.kuzushiRevision) &&
    isIsoTimestamp(value.observed.generatedAt) &&
    isNonnegativeFinite(value.observed.durationMs) &&
    isNonemptyString(value.observed.runId) &&
    isModelList(value.observed.models) &&
    isNonnegativeInteger(value.observed.llmCallCount) &&
    typeof value.observed.llmAuditComplete === "boolean" &&
    optionalSha256Digest(value.observed.configHash) &&
    (value.observed.spendSource === "canonical-run-summary" ||
      value.observed.spendSource === "deterministic-fixture")
  );
}

function isComparable(value: unknown, dataset: string): value is BenchmarkComparableProvenance {
  if (!isRecord(value) || value.datasetName !== dataset || value.scoringMode !== "strict-cwe-v1") {
    return false;
  }
  return (
    ["datasetDigest", "harnessDigest", "scanConfigDigest"].every((field) =>
      isSha256Digest(value[field]),
    ) &&
    ["datasetName", "datasetRevision", "harnessContractVersion", "modelIdentity"].every((field) =>
      isNonemptyString(value[field]),
    )
  );
}

function isSpendReceipt(value: unknown): value is BenchmarkSpendReceipt {
  if (!isRecord(value) || value.measured !== true || !isNonemptyString(value.runId)) return false;
  return (
    (value.source === "canonical-run-summary" || value.source === "deterministic-fixture") &&
    isModelList(value.models) &&
    isNonnegativeInteger(value.llmCallCount) &&
    typeof value.llmAuditComplete === "boolean" &&
    optionalSha256Digest(value.configHash) &&
    (value.llmCallCount === 0) === (value.models.length === 0)
  );
}

function isCweMetrics(value: unknown): value is CweMetrics {
  return (
    isRecord(value) &&
    COUNT_FIELDS.every((key) => isNonnegativeInteger(value[key])) &&
    PROBABILITY_FIELDS.every((key) => isProbability(value[key]))
  );
}

function assertSharedProvenance(
  reference: BenchmarkMetrics,
  candidate: BenchmarkMetrics,
  source: string,
): void {
  const sharedFields = COMPARABLE_FIELDS.filter((field) => !field.startsWith("dataset"));
  const differences = sharedFields.flatMap((field) =>
    reference.provenance.comparable[field] === candidate.provenance.comparable[field]
      ? []
      : [
          `${field}: ${reference.provenance.comparable[field]} != ${candidate.provenance.comparable[field]}`,
        ],
  );
  if (reference.provenance.mode !== candidate.provenance.mode) {
    differences.unshift(`mode: ${reference.provenance.mode} != ${candidate.provenance.mode}`);
  }
  if (differences.length > 0)
    throw new Error(`Mixed benchmark provenance in ${source}: ${differences.join("; ")}`);
}

function provenanceDifferences(before: BenchmarkMetrics, after: BenchmarkMetrics): string[] {
  const differences = COMPARABLE_FIELDS.flatMap((field) => {
    const left = before.provenance.comparable[field];
    const right = after.provenance.comparable[field];
    return left === right ? [] : [`${field}: ${left} != ${right}`];
  });
  if (before.provenance.mode !== after.provenance.mode) {
    differences.unshift(`mode: ${before.provenance.mode} != ${after.provenance.mode}`);
  }
  return differences;
}

function datasetRevision(dataset: GroundTruthDataset): string {
  return `${dataset.repoUrl.replace(/\.git$/i, "")}@${dataset.repoRef}`;
}

function harnessDigest(): string {
  const hash = createHash("sha256");
  for (const file of BENCHMARK_CONTRACT_FILES) {
    hash.update(file);
    hash.update("\0");
    hash.update(readFileSync(join(__dirname, file)));
    hash.update("\0");
  }
  return `sha256:${hash.digest("hex")}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonemptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isSha256Digest(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f\d]{64}$/.test(value);
}

function isIsoTimestamp(value: unknown): value is string {
  if (!isNonemptyString(value)) return false;
  const date = new Date(value);
  return Number.isFinite(date.valueOf()) && date.toISOString() === value;
}

function isNonnegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function isProbability(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

function isNonnegativeFinite(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function isModelList(value: unknown): value is string[] {
  if (!Array.isArray(value) || !value.every(isNonemptyString)) return false;
  return value.every((model, index) => index === 0 || value[index - 1]! < model);
}

function optionalSha256Digest(value: unknown): boolean {
  return value === undefined || isSha256Digest(value);
}

function arraysEqual(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

import type { BenchmarkSpendReceipt, BenchmarkSpendSource, SarifLog } from "./types.js";

export interface RecordedBenchmarkSpend {
  costUsd: number;
  receipt: BenchmarkSpendReceipt;
}

const SPEND_SOURCES = new Set<BenchmarkSpendSource>([
  "canonical-run-summary",
  "deterministic-fixture",
]);

export function recordedBenchmarkSpend(sarif: SarifLog): RecordedBenchmarkSpend {
  rejectRunLevelAggregateSpend(sarif);
  rejectLegacyRunSpend(sarif);
  const aggregate = rootAggregateSpend(sarif);
  return {
    costUsd: requiredCost(aggregate.totalCostUsd),
    receipt: {
      measured: true,
      runId: requiredString(aggregate.runId, "runId"),
      source: requiredSource(aggregate.source),
      models: requiredModels(aggregate.models),
      llmCallCount: requiredCallCount(aggregate.llmCallCount),
      llmAuditComplete: requiredBoolean(aggregate.llmAuditComplete, "llmAuditComplete"),
      ...optionalConfigHash(aggregate.configHash),
    },
  };
}

function rootAggregateSpend(sarif: SarifLog): Record<string, unknown> {
  const benchmark = recordAt(sarif.properties, "kuzushiBenchmark");
  if (!benchmark) {
    throw new Error("SARIF is missing canonical root benchmark spend metadata");
  }
  if (benchmark.schemaVersion !== 2) {
    throw new Error("SARIF benchmark spend schemaVersion must be 2");
  }
  const aggregate = recordAt(benchmark, "aggregateSpend");
  if (!aggregate) throw new Error("SARIF benchmark aggregateSpend is missing or invalid");
  return aggregate;
}

function rejectRunLevelAggregateSpend(sarif: SarifLog): void {
  const duplicates = sarif.runs.filter((run) =>
    Boolean(recordAt(recordAt(run.properties, "kuzushiBenchmark"), "aggregateSpend")),
  );
  if (duplicates.length > 0) {
    throw new Error(
      "SARIF benchmark spend is ambiguous: aggregateSpend must exist only at the document root",
    );
  }
}

function rejectLegacyRunSpend(sarif: SarifLog): void {
  const hasLegacySpend = sarif.runs.some((run) => {
    const summary = recordAt(run.properties, "summary");
    return summary?.totalCostUsd !== undefined;
  });
  if (hasLegacySpend) {
    throw new Error(
      "SARIF benchmark spend is ambiguous: per-run summary.totalCostUsd is not an aggregate receipt",
    );
  }
}

function requiredCost(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new Error("SARIF benchmark totalCostUsd must be a finite nonnegative number");
  }
  return value;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`SARIF benchmark ${label} must be a nonempty string`);
  }
  return value.trim();
}

function requiredSource(value: unknown): BenchmarkSpendSource {
  const source = requiredString(value, "source") as BenchmarkSpendSource;
  if (!SPEND_SOURCES.has(source)) throw new Error(`Unsupported benchmark spend source: ${source}`);
  return source;
}

function requiredModels(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 64) {
    throw new Error("SARIF benchmark models must be an array with at most 64 entries");
  }
  const models = value.map((model) => requiredString(model, "models[]"));
  if (models.some((model, index) => index > 0 && models[index - 1]! >= model)) {
    throw new Error("SARIF benchmark models must be sorted and unique");
  }
  return models;
}

function requiredCallCount(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > 1_000_000) {
    throw new Error("SARIF benchmark llmCallCount must be an integer from 0 through 1000000");
  }
  return value as number;
}

function requiredBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new Error(`SARIF benchmark ${label} must be a boolean`);
  return value;
}

function optionalConfigHash(value: unknown): { configHash?: string } {
  if (value === undefined) return {};
  const hash = requiredString(value, "configHash");
  if (!/^sha256:[a-f\d]{64}$/u.test(hash)) {
    throw new Error("SARIF benchmark configHash must be a sha256 digest");
  }
  return { configHash: hash };
}

function recordAt(
  value: Record<string, unknown> | null | undefined,
  key: string,
): Record<string, unknown> | null {
  const nested = value?.[key];
  return isRecord(nested) ? nested : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

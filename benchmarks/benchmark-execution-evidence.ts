import type {
  BenchmarkExecutionMode,
  BenchmarkProvenanceInput,
  BenchmarkSpendReceipt,
} from "./types.js";

export function assertExecutionMatchesDeclaration(
  declaration: BenchmarkProvenanceInput,
  receipt: BenchmarkSpendReceipt,
): void {
  if (declaration.executionMode === "deterministic-fixture") {
    assertDeterministicReceipt(receipt);
    return;
  }
  assertRealModelReceipt(declaration.modelIdentity, receipt);
}

export function executionEvidenceMatches(
  mode: BenchmarkExecutionMode,
  modelIdentity: string,
  receipt: BenchmarkSpendReceipt,
): boolean {
  try {
    assertReceiptForMode(mode, modelIdentity, receipt);
    return true;
  } catch {
    return false;
  }
}

function assertReceiptForMode(
  mode: BenchmarkExecutionMode,
  modelIdentity: string,
  receipt: BenchmarkSpendReceipt,
): void {
  if (mode === "deterministic-fixture") {
    assertDeterministicReceipt(receipt);
    return;
  }
  assertRealModelReceipt(modelIdentity, receipt);
}

function assertDeterministicReceipt(receipt: BenchmarkSpendReceipt): void {
  assertNoModelCalls(receipt);
  if (receipt.source === "canonical-run-summary" && receipt.configHash === undefined) {
    throw new Error("a live deterministic scan receipt requires the outer run configHash");
  }
}

function assertNoModelCalls(receipt: BenchmarkSpendReceipt): void {
  if (receipt.llmCallCount !== 0 || receipt.models.length !== 0 || !receipt.llmAuditComplete) {
    throw new Error(
      "deterministic-fixture provenance requires a complete receipt with zero model calls",
    );
  }
}

function assertRealModelReceipt(modelIdentity: string, receipt: BenchmarkSpendReceipt): void {
  assertCanonicalSource(receipt);
  assertCompleteModelAudit(receipt);
  assertObservedModel(modelIdentity, receipt.models);
  if (receipt.configHash === undefined) {
    throw new Error("real-model provenance requires the outer run configHash");
  }
}

function assertCanonicalSource(receipt: BenchmarkSpendReceipt): void {
  if (receipt.source !== "canonical-run-summary") {
    throw new Error("real-model provenance requires canonical-run-summary spend evidence");
  }
}

function assertCompleteModelAudit(receipt: BenchmarkSpendReceipt): void {
  if (!receipt.llmAuditComplete || receipt.llmCallCount === 0) {
    throw new Error("real-model provenance requires a complete audit with an observed model call");
  }
}

function assertObservedModel(modelIdentity: string, models: string[]): void {
  if (models.length !== 1 || models[0] !== modelIdentity) {
    throw new Error("real-model provenance modelIdentity does not match the observed model set");
  }
}

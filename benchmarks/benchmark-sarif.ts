import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  type Stats,
} from "node:fs";
import { TextDecoder } from "node:util";
import type { SarifLog } from "./types.js";

const MAX_SARIF_BYTES = 32 * 1024 * 1024;
const MAX_SARIF_RUNS = 128;
const MAX_SARIF_RESULTS = 20_000;
const MAX_SARIF_RULES = 20_000;
const MAX_LOCATIONS_PER_RESULT = 64;
const MAX_SUPPRESSIONS_PER_RESULT = 64;
const MAX_TAGS_PER_RULE = 256;
const MAX_FINGERPRINTS_PER_RESULT = 64;
const MAX_TOTAL_KNOWN_STRING_BYTES = 16 * 1024 * 1024;

class SarifBudget {
  private resultCount = 0;
  private ruleCount = 0;
  private stringBytes = 0;

  addResults(count: number): void {
    this.resultCount += count;
    if (this.resultCount > MAX_SARIF_RESULTS) {
      throw new Error(`SARIF contains more than ${MAX_SARIF_RESULTS} results`);
    }
  }

  addRules(count: number): void {
    this.ruleCount += count;
    if (this.ruleCount > MAX_SARIF_RULES) {
      throw new Error(`SARIF contains more than ${MAX_SARIF_RULES} rules`);
    }
  }

  string(value: unknown, label: string, maxBytes: number): string {
    if (typeof value !== "string") throw new Error(`${label} must be a string`);
    const bytes = Buffer.byteLength(value);
    if (bytes > maxBytes) throw new Error(`${label} exceeds ${maxBytes} bytes`);
    this.stringBytes += bytes;
    if (this.stringBytes > MAX_TOTAL_KNOWN_STRING_BYTES) {
      throw new Error("SARIF known string material exceeds the aggregate byte budget");
    }
    return value;
  }
}

export function loadBenchmarkSarif(path: string): SarifLog {
  const body = readSarifFile(path);
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch (error) {
    throw new Error(`SARIF is not valid JSON: ${errorMessage(error)}`);
  }
  return validateBenchmarkSarif(parsed);
}

export function validateBenchmarkSarif(value: unknown): SarifLog {
  const budget = new SarifBudget();
  const root = validatedRoot(value, budget);
  const runs = validatedRuns(root.runs);
  runs.forEach((run, index) => {
    validateRun(run, index, budget);
  });
  optionalRecord(root.properties, "SARIF.properties");
  return value as SarifLog;
}

function validatedRoot(value: unknown, budget: SarifBudget): Record<string, unknown> {
  const root = requiredRecord(value, "SARIF");
  if (root.$schema !== undefined) budget.string(root.$schema, "SARIF.$schema", 4_096);
  if (budget.string(root.version, "SARIF.version", 64) !== "2.1.0") {
    throw new Error("SARIF.version must be 2.1.0");
  }
  return root;
}

function validatedRuns(value: unknown): unknown[] {
  const runs = requiredArray(value, "SARIF.runs");
  if (runs.length === 0) throw new Error("No runs found in SARIF file");
  if (runs.length > MAX_SARIF_RUNS) {
    throw new Error(`SARIF contains more than ${MAX_SARIF_RUNS} runs`);
  }
  return runs;
}

function validateRun(value: unknown, index: number, budget: SarifBudget): void {
  const label = `SARIF.runs[${index}]`;
  const run = requiredRecord(value, label);
  const tool = requiredRecord(run.tool, `${label}.tool`);
  const driver = requiredRecord(tool.driver, `${label}.tool.driver`);
  budget.string(driver.name, `${label}.tool.driver.name`, 1_024);
  const rules = optionalArray(driver.rules, `${label}.tool.driver.rules`);
  budget.addRules(rules.length);
  rules.forEach((rule, ruleIndex) => {
    validateRule(rule, `${label}.rules[${ruleIndex}]`, budget);
  });
  const results = requiredArray(run.results, `${label}.results`);
  budget.addResults(results.length);
  results.forEach((result, resultIndex) => {
    validateResult(result, `${label}.results[${resultIndex}]`, budget);
  });
  optionalRecord(run.properties, `${label}.properties`);
}

function validateRule(value: unknown, label: string, budget: SarifBudget): void {
  const rule = requiredRecord(value, label);
  budget.string(rule.id, `${label}.id`, 1_024);
  const properties = optionalRecord(rule.properties, `${label}.properties`);
  if (!properties) return;
  const tags = optionalArray(properties.tags, `${label}.properties.tags`);
  assertArrayLimit(tags, MAX_TAGS_PER_RULE, `${label}.properties.tags`);
  tags.forEach((tag, index) => {
    budget.string(tag, `${label}.tags[${index}]`, 1_024);
  });
}

function validateResult(value: unknown, label: string, budget: SarifBudget): void {
  const result = requiredRecord(value, label);
  requiredRuleId(result.ruleId, label, budget);
  const message = requiredRecord(result.message, `${label}.message`);
  budget.string(message.text, `${label}.message.text`, 32 * 1024);
  validateLocations(result.locations, label, budget);
  validateFingerprints(result.fingerprints, label, budget);
  validateResultProperties(result.properties, label, budget);
  validateSuppressions(result.suppressions, label, budget);
}

function requiredRuleId(value: unknown, label: string, budget: SarifBudget): void {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${label} is missing a nonempty ruleId`);
  }
  budget.string(value, `${label}.ruleId`, 1_024);
}

function validateLocations(value: unknown, label: string, budget: SarifBudget): void {
  const locations = optionalArray(value, `${label}.locations`);
  assertArrayLimit(locations, MAX_LOCATIONS_PER_RESULT, `${label}.locations`);
  locations.forEach((location, index) => {
    validateLocation(location, `${label}.locations[${index}]`, budget);
  });
}

function validateLocation(value: unknown, label: string, budget: SarifBudget): void {
  const record = requiredRecord(value, label);
  const physical = optionalRecord(record.physicalLocation, `${label}.physicalLocation`);
  if (!physical) return;
  validateArtifactLocation(physical.artifactLocation, label, budget);
  validateRegion(physical.region, label);
}

function validateArtifactLocation(value: unknown, label: string, budget: SarifBudget): void {
  const artifact = optionalRecord(value, `${label}.physicalLocation.artifactLocation`);
  if (artifact?.uri !== undefined) budget.string(artifact.uri, `${label}.uri`, 4_096);
}

function validateRegion(value: unknown, label: string): void {
  const region = optionalRecord(value, `${label}.physicalLocation.region`);
  if (region?.startLine !== undefined) {
    requiredPositiveInteger(region.startLine, `${label}.startLine`);
  }
  if (region?.endLine !== undefined) {
    requiredPositiveInteger(region.endLine, `${label}.endLine`);
  }
}

function validateFingerprints(value: unknown, label: string, budget: SarifBudget): void {
  const fingerprints = optionalRecord(value, `${label}.fingerprints`);
  if (!fingerprints) return;
  const entries = Object.entries(fingerprints);
  if (entries.length > MAX_FINGERPRINTS_PER_RESULT) {
    throw new Error(`${label}.fingerprints has too many entries`);
  }
  for (const [key, fingerprint] of entries) {
    budget.string(key, `${label}.fingerprint key`, 1_024);
    budget.string(fingerprint, `${label}.fingerprints.${key}`, 4_096);
  }
}

function validateResultProperties(value: unknown, label: string, budget: SarifBudget): void {
  const properties = optionalRecord(value, `${label}.properties`);
  if (!properties) return;
  validateKnownStringProperties(properties, label, budget);
  validateOptionalFinite(properties.confidence, `${label}.properties.confidence`);
  validateOptionalBoolean(properties.exploitable, `${label}.properties.exploitable`);
}

function validateKnownStringProperties(
  properties: Record<string, unknown>,
  label: string,
  budget: SarifBudget,
): void {
  for (const key of ["verdict", "rationale", "kuzushiCwe", "kuzushiIdentityId"]) {
    if (properties[key] !== undefined) {
      budget.string(properties[key], `${label}.properties.${key}`, 32 * 1024);
    }
  }
}

function validateOptionalFinite(value: unknown, label: string): void {
  if (value !== undefined && !isFiniteNumber(value)) {
    throw new Error(`${label} must be finite`);
  }
}

function validateOptionalBoolean(value: unknown, label: string): void {
  if (value !== undefined && typeof value !== "boolean") {
    throw new Error(`${label} must be a boolean`);
  }
}

function validateSuppressions(value: unknown, label: string, budget: SarifBudget): void {
  const suppressions = optionalArray(value, `${label}.suppressions`);
  assertArrayLimit(suppressions, MAX_SUPPRESSIONS_PER_RESULT, `${label}.suppressions`);
  suppressions.forEach((suppression, index) => {
    const itemLabel = `${label}.suppressions[${index}]`;
    const item = requiredRecord(suppression, itemLabel);
    budget.string(item.kind, `${itemLabel}.kind`, 256);
    if (item.justification !== undefined) {
      budget.string(item.justification, `${itemLabel}.justification`, 32 * 1024);
    }
  });
}

function readSarifFile(path: string): string {
  const before = lstatSync(path);
  assertRegularSarif(path, before);
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || before.dev !== opened.dev || before.ino !== opened.ino) {
      throw new Error(`SARIF changed while it was being opened: ${path}`);
    }
    assertSarifSize(path, opened.size);
    return readBoundedUtf8(descriptor, path);
  } finally {
    closeSync(descriptor);
  }
}

function assertRegularSarif(path: string, metadata: Stats): void {
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`SARIF must be a regular non-symlink file: ${path}`);
  }
  assertSarifSize(path, metadata.size);
}

function assertSarifSize(path: string, size: number): void {
  if (size > MAX_SARIF_BYTES) throw new Error(`SARIF exceeds ${MAX_SARIF_BYTES} bytes: ${path}`);
}

function readBoundedUtf8(descriptor: number, path: string): string {
  const buffer = Buffer.alloc(MAX_SARIF_BYTES + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const count = readSync(descriptor, buffer, offset, buffer.length - offset, null);
    if (count === 0) break;
    offset += count;
  }
  assertSarifSize(path, offset);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, offset));
  } catch {
    throw new Error(`SARIF is not valid UTF-8: ${path}`);
  }
}

function requiredRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function optionalRecord(value: unknown, label: string): Record<string, unknown> | undefined {
  return value === undefined ? undefined : requiredRecord(value, label);
}

function requiredArray(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function optionalArray(value: unknown, label: string): unknown[] {
  return value === undefined ? [] : requiredArray(value, label);
}

function assertArrayLimit(value: unknown[], limit: number, label: string): void {
  if (value.length > limit) throw new Error(`${label} contains more than ${limit} items`);
}

function requiredPositiveInteger(value: unknown, label: string): void {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
}

function isFiniteNumber(value: unknown): boolean {
  return typeof value === "number" && Number.isFinite(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

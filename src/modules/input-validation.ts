import { safeJsonStringify } from "../utils/safe-json.js";
import type { JSONSchema } from "./schema.js";

export const MAX_TOOL_INPUT_BYTES = 1024 * 1024;

export interface ToolInputValidationIssue {
  path: string;
  message: string;
}

export interface ToolInputValidationResult {
  ok: boolean;
  issues: ToolInputValidationIssue[];
}

const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export function validateToolInput(input: unknown, schema: JSONSchema): ToolInputValidationResult {
  const issues: ToolInputValidationIssue[] = [];
  const serialized = safeJsonStringify(input);
  const bytes = Buffer.byteLength(serialized ?? "", "utf8");
  if (bytes > MAX_TOOL_INPUT_BYTES) {
    issues.push({
      path: "<root>",
      message: `payload exceeds ${MAX_TOOL_INPUT_BYTES} bytes`,
    });
    return { ok: false, issues };
  }

  validateValue(input, schema, "<root>", issues, new WeakSet<object>());
  return { ok: issues.length === 0, issues };
}

export function normalizeToolInputKeys(input: unknown, schema: JSONSchema): unknown {
  return normalizeValueKeys(input, schema, new WeakMap<object, unknown>());
}

export function formatToolInputValidationError(
  qualifiedName: string,
  issues: ReadonlyArray<ToolInputValidationIssue>,
): string {
  const lines = issues.map((issue) => `  - ${issue.path}: ${issue.message}`);
  return `Invalid input for tool "${qualifiedName}":\n${lines.join("\n")}`;
}

function normalizeValueKeys(
  value: unknown,
  schema: JSONSchema,
  seen: WeakMap<object, unknown>,
): unknown {
  if (Array.isArray(value)) {
    const items = schema.items;
    if (!isSchemaRecord(items)) return value;
    return value.map((item) => normalizeValueKeys(item, items, seen));
  }
  if (!isPlainRecord(value)) return value;
  if (seen.has(value)) return seen.get(value);

  const properties = readProperties(schema);
  const additional = schema.additionalProperties;
  const hasObjectShape =
    Object.keys(properties).length > 0 ||
    schema.required !== undefined ||
    schema.additionalProperties !== undefined;
  if (!hasObjectShape) return value;

  const out: Record<string, unknown> = {};
  seen.set(value, out);

  const canonicalByLower = new Map<string, string | null>();
  for (const key of Object.keys(properties)) {
    const lower = key.toLowerCase();
    const previous = canonicalByLower.get(lower);
    canonicalByLower.set(lower, previous === undefined ? key : previous === key ? key : null);
  }
  const exactKeysPresent = new Set(
    Object.keys(value).filter((key) => Object.hasOwn(properties, key)),
  );

  for (const [key, child] of Object.entries(value)) {
    if (DANGEROUS_KEYS.has(key)) {
      out[key] = child;
      continue;
    }

    let outputKey = key;
    let childSchema = Object.hasOwn(properties, key) ? properties[key] : undefined;
    if (!childSchema) {
      const canonical = canonicalByLower.get(key.toLowerCase());
      if (canonical && Object.hasOwn(properties, canonical)) {
        if (exactKeysPresent.has(canonical)) continue;
        outputKey = canonical;
        childSchema = properties[canonical];
      }
    }

    if (childSchema) {
      out[outputKey] = normalizeValueKeys(child, childSchema, seen);
    } else if (isSchemaRecord(additional)) {
      out[outputKey] = normalizeValueKeys(child, additional, seen);
    } else {
      out[outputKey] = child;
    }
  }

  return out;
}

function validateValue(
  value: unknown,
  schema: JSONSchema,
  path: string,
  issues: ToolInputValidationIssue[],
  seen: WeakSet<object>,
): void {
  if (issues.length > 50) return;

  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
    issues.push({ path, message: `must be one of ${schema.enum.map(String).join("|")}` });
    return;
  }

  const expectedTypes = readExpectedTypes(schema);
  if (expectedTypes.length > 0 && !expectedTypes.some((type) => matchesType(value, type))) {
    issues.push({
      path,
      message: `expected ${expectedTypes.join("|")}, got ${jsonTypeOf(value)}`,
    });
    return;
  }

  const effectiveType =
    expectedTypes.length > 0
      ? expectedTypes.find((type) => matchesType(value, type))
      : inferSchemaType(schema);

  switch (effectiveType) {
    case "object":
      validateObject(value, schema, path, issues, seen);
      return;
    case "array":
      validateArray(value, schema, path, issues, seen);
      return;
    case "string":
      validateString(value, schema, path, issues);
      return;
    case "number":
    case "integer":
      validateNumber(value, schema, path, issues);
      return;
    default:
      if (
        typeof value === "undefined" ||
        typeof value === "function" ||
        typeof value === "symbol"
      ) {
        issues.push({ path, message: `unsupported JSON value ${typeof value}` });
      }
  }
}

function validateObject(
  value: unknown,
  schema: JSONSchema,
  path: string,
  issues: ToolInputValidationIssue[],
  seen: WeakSet<object>,
): void {
  if (!isPlainRecord(value)) {
    issues.push({ path, message: `expected object, got ${jsonTypeOf(value)}` });
    return;
  }
  if (seen.has(value)) {
    issues.push({ path, message: "circular object references are not valid tool input" });
    return;
  }
  seen.add(value);

  const required = Array.isArray(schema.required)
    ? schema.required.filter((item): item is string => typeof item === "string")
    : [];
  for (const key of required) {
    if (!(key in value) || value[key] === undefined) {
      issues.push({ path: childPath(path, key), message: "is required" });
    }
  }

  const properties = readProperties(schema);
  const additional = schema.additionalProperties;

  for (const [key, child] of Object.entries(value)) {
    if (DANGEROUS_KEYS.has(key)) {
      issues.push({ path: childPath(path, key), message: "reserved object key is not allowed" });
      continue;
    }

    const propertySchema = properties[key];
    if (propertySchema) {
      validateValue(child, propertySchema, childPath(path, key), issues, seen);
      continue;
    }

    if (additional === true) continue;
    if (isSchemaRecord(additional)) {
      validateValue(child, additional, childPath(path, key), issues, seen);
      continue;
    }
    issues.push({ path: childPath(path, key), message: "unknown property" });
  }

  seen.delete(value);
}

function validateArray(
  value: unknown,
  schema: JSONSchema,
  path: string,
  issues: ToolInputValidationIssue[],
  seen: WeakSet<object>,
): void {
  if (!Array.isArray(value)) {
    issues.push({ path, message: `expected array, got ${jsonTypeOf(value)}` });
    return;
  }
  const minItems = readFiniteNumber(schema.minItems);
  if (minItems !== undefined && value.length < minItems) {
    issues.push({ path, message: `must contain at least ${minItems} item(s)` });
  }
  const maxItems = readFiniteNumber(schema.maxItems);
  if (maxItems !== undefined && value.length > maxItems) {
    issues.push({ path, message: `must contain at most ${maxItems} item(s)` });
  }

  if (isSchemaRecord(schema.items)) {
    for (let i = 0; i < value.length; i++) {
      validateValue(value[i], schema.items, `${path}[${i}]`, issues, seen);
    }
  }
}

function validateString(
  value: unknown,
  schema: JSONSchema,
  path: string,
  issues: ToolInputValidationIssue[],
): void {
  if (typeof value !== "string") return;
  const minLength = readFiniteNumber(schema.minLength);
  if (minLength !== undefined && value.length < minLength) {
    issues.push({ path, message: `must be at least ${minLength} character(s)` });
  }
  const maxLength = readFiniteNumber(schema.maxLength);
  if (maxLength !== undefined && value.length > maxLength) {
    issues.push({ path, message: `must be at most ${maxLength} character(s)` });
  }
  if (typeof schema.pattern === "string") {
    try {
      if (!new RegExp(schema.pattern).test(value)) {
        issues.push({ path, message: `must match pattern ${schema.pattern}` });
      }
    } catch {
      issues.push({ path, message: "schema pattern is invalid" });
    }
  }
}

function validateNumber(
  value: unknown,
  schema: JSONSchema,
  path: string,
  issues: ToolInputValidationIssue[],
): void {
  if (typeof value !== "number") return;
  const minimum = readFiniteNumber(schema.minimum);
  if (minimum !== undefined && value < minimum) {
    issues.push({ path, message: `must be >= ${minimum}` });
  }
  const maximum = readFiniteNumber(schema.maximum);
  if (maximum !== undefined && value > maximum) {
    issues.push({ path, message: `must be <= ${maximum}` });
  }
}

function readExpectedTypes(schema: JSONSchema): string[] {
  if (typeof schema.type === "string") return [schema.type];
  if (Array.isArray(schema.type)) {
    return schema.type.filter((item): item is string => typeof item === "string");
  }
  return [];
}

function inferSchemaType(schema: JSONSchema): string {
  if (schema.properties || schema.required || schema.additionalProperties !== undefined) {
    return "object";
  }
  if (schema.items) return "array";
  return "object";
}

function matchesType(value: unknown, type: string): boolean {
  switch (type) {
    case "object":
      return isPlainRecord(value);
    case "array":
      return Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "boolean":
      return typeof value === "boolean";
    case "null":
      return value === null;
    default:
      return true;
  }
}

function jsonTypeOf(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number" && Number.isInteger(value)) return "integer";
  return typeof value;
}

function readProperties(schema: JSONSchema): Record<string, JSONSchema> {
  if (!isSchemaRecord(schema.properties)) return {};
  const result: Record<string, JSONSchema> = {};
  for (const [key, value] of Object.entries(schema.properties)) {
    if (isSchemaRecord(value)) result[key] = value;
  }
  return result;
}

function isSchemaRecord(value: unknown): value is JSONSchema {
  return isPlainRecord(value);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function readFiniteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function childPath(parent: string, key: string): string {
  return parent === "<root>" ? key : `${parent}.${key}`;
}

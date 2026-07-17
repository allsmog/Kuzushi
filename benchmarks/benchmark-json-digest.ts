import { createHash } from "node:crypto";

export function digestJson(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function canonicalJson(value: unknown): string {
  const scalar = canonicalScalar(value);
  if (scalar !== null) return scalar;
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) return canonicalRecord(value);
  throw new Error("Benchmark provenance inputs must contain only finite JSON values");
}

function canonicalScalar(value: unknown): string | null {
  if (value === null) return "null";
  if (typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  return canonicalNumber(value);
}

function canonicalNumber(value: unknown): string | null {
  if (typeof value !== "number") return null;
  return Number.isFinite(value) ? JSON.stringify(value) : null;
}

function canonicalRecord(value: Record<string, unknown>): string {
  const fields = Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
  return `{${fields.join(",")}}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

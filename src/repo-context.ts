import type { EnrichedRepoContext, FileIndex, RepoContext } from "./types.js";
import { isRecord } from "./utils.js";

export function coerceRepoContext(value: unknown): RepoContext | undefined {
  // Unwrap TaskHandoff envelope if present
  if (isRecord(value) && value["__handoff"] === true && "output" in value) {
    return coerceRepoContext(value["output"]);
  }

  if (!isRecord(value)) {
    return undefined;
  }

  // Unwrap ContextGathererOutput composite shape
  if ("repoContext" in value && isRecord(value["repoContext"])) {
    return coerceRepoContext(value["repoContext"]);
  }

  if ("base" in value) {
    return coerceRepoContext(value["base"]);
  }

  const repoContext: RepoContext = {
    languages: asStringArray(value["languages"]),
    frameworks: asStringArray(value["frameworks"]),
    authPatterns: asStringArray(value["authPatterns"]),
    sanitizationLibs: asStringArray(value["sanitizationLibs"]),
    ormOrDb: asStringArray(value["ormOrDb"]),
    entryPoints: asStringArray(value["entryPoints"]),
  };

  const hasAnyValue =
    repoContext.languages.length > 0 ||
    repoContext.frameworks.length > 0 ||
    repoContext.authPatterns.length > 0 ||
    repoContext.sanitizationLibs.length > 0 ||
    repoContext.ormOrDb.length > 0 ||
    repoContext.entryPoints.length > 0;

  return hasAnyValue ? repoContext : undefined;
}

export function coerceContextEnrichment(
  value: unknown,
): EnrichedRepoContext["enrichment"] | undefined {
  if (isRecord(value) && value["__handoff"] === true && "output" in value) {
    return coerceContextEnrichment(value["output"]);
  }

  if (!isRecord(value)) {
    return undefined;
  }

  const candidate =
    "enrichment" in value && isRecord(value["enrichment"]) ? value["enrichment"] : value;

  if (!isRecord(candidate)) {
    return undefined;
  }

  const enrichment: EnrichedRepoContext["enrichment"] = {
    customMiddleware: asObjectArray(candidate["customMiddleware"], (item) => ({
      name: asString(item["name"]),
      filePath: asString(item["filePath"]),
      purpose: asString(item["purpose"]),
      appliesTo: asOptionalString(item["appliesTo"]),
    })),
    customSanitizers: asObjectArray(candidate["customSanitizers"], (item) => ({
      name: asString(item["name"]),
      filePath: asString(item["filePath"]),
      sanitizationType: asString(item["sanitizationType"]),
      usedBy: asOptionalString(item["usedBy"]),
    })),
    trustBoundaries: asObjectArray(candidate["trustBoundaries"], (item) => ({
      name: asString(item["name"]),
      description: asString(item["description"]),
      entryPoints: asStringArray(item["entryPoints"]),
    })),
    dataClassifications: asObjectArray(candidate["dataClassifications"], (item) => {
      const sensitivity = asString(item["sensitivity"]);
      if (!["public", "internal", "confidential", "restricted"].includes(sensitivity)) {
        return null;
      }
      return {
        dataType: asString(item["dataType"]),
        sensitivity: sensitivity as "public" | "internal" | "confidential" | "restricted",
        locations: asStringArray(item["locations"]),
      };
    }),
    architecturalNotes: asStringArray(candidate["architecturalNotes"]),
  };

  const hasAnyValue =
    enrichment.customMiddleware.length > 0 ||
    enrichment.customSanitizers.length > 0 ||
    enrichment.trustBoundaries.length > 0 ||
    enrichment.dataClassifications.length > 0 ||
    enrichment.architecturalNotes.length > 0;

  return hasAnyValue ? enrichment : undefined;
}

export function formatRepoContext(repoContext: RepoContext | undefined): string[] {
  if (!repoContext) {
    return [];
  }

  const lines: string[] = [];
  if (repoContext.languages.length > 0) {
    lines.push(`Languages: ${repoContext.languages.join(", ")}`);
  }
  if (repoContext.frameworks.length > 0) {
    lines.push(`Frameworks: ${repoContext.frameworks.join(", ")}`);
  }
  if (repoContext.authPatterns.length > 0) {
    lines.push(`Auth: ${repoContext.authPatterns.join(", ")}`);
  }
  if (repoContext.ormOrDb.length > 0) {
    lines.push(`ORM/DB: ${repoContext.ormOrDb.join(", ")}`);
  }
  if (repoContext.sanitizationLibs.length > 0) {
    lines.push(`Sanitization: ${repoContext.sanitizationLibs.join(", ")}`);
  }
  if (repoContext.entryPoints.length > 0) {
    lines.push(`Entry points: ${repoContext.entryPoints.join(", ")}`);
  }

  return lines;
}

export function formatEnrichedRepoContext(
  enrichment: EnrichedRepoContext["enrichment"] | undefined,
): string[] {
  if (!enrichment) return [];

  const lines: string[] = [];

  if (enrichment.customMiddleware.length > 0) {
    lines.push("Custom middleware:");
    for (const mw of enrichment.customMiddleware) {
      lines.push(
        `  - ${mw.name} (${mw.filePath}): ${mw.purpose}${mw.appliesTo ? ` [applies to: ${mw.appliesTo}]` : ""}`,
      );
    }
  }

  if (enrichment.customSanitizers.length > 0) {
    lines.push("Custom sanitizers:");
    for (const san of enrichment.customSanitizers) {
      lines.push(
        `  - ${san.name} (${san.filePath}): ${san.sanitizationType}${san.usedBy ? ` [used by: ${san.usedBy}]` : ""}`,
      );
    }
  }

  if (enrichment.trustBoundaries.length > 0) {
    lines.push("Trust boundaries:");
    for (const tb of enrichment.trustBoundaries) {
      lines.push(`  - ${tb.name}: ${tb.description}`);
    }
  }

  if (enrichment.dataClassifications.length > 0) {
    lines.push("Data classifications:");
    for (const dc of enrichment.dataClassifications) {
      lines.push(`  - ${dc.dataType} (${dc.sensitivity})`);
    }
  }

  if (enrichment.architecturalNotes.length > 0) {
    lines.push("Architectural notes:");
    for (const note of enrichment.architecturalNotes) {
      lines.push(`  - ${note}`);
    }
  }

  return lines;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.map((item) => (typeof item === "string" ? item.trim() : "")).filter(Boolean);
}

function asObjectArray<T>(value: unknown, map: (item: Record<string, unknown>) => T | null): T[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const result: T[] = [];
  for (const item of value) {
    if (!isRecord(item)) {
      continue;
    }
    const mapped = map(item);
    if (mapped) {
      result.push(mapped);
    }
  }
  return result;
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function asOptionalString(value: unknown): string | undefined {
  const normalized = asString(value);
  return normalized || undefined;
}

export function coerceFileIndex(value: unknown): FileIndex | undefined {
  if (isRecord(value) && value["__handoff"] === true && "output" in value) {
    return coerceFileIndex(value["output"]);
  }
  if (!isRecord(value)) return undefined;
  if ("fileIndex" in value && isRecord(value["fileIndex"])) {
    return value["fileIndex"] as FileIndex;
  }
  if ("tree" in value && Array.isArray(value["tree"])) {
    return value as FileIndex;
  }
  return undefined;
}

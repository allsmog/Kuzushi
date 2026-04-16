import * as fs from "node:fs";
import * as path from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { isPathWithinRoot } from "./utils.js";

export type ConfigFormat = "json" | "yaml";

export function detectConfigFormat(filePath: string): ConfigFormat {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".yaml" || ext === ".yml") return "yaml";
  return "json";
}

export function parseConfigFile(content: string, format: ConfigFormat): unknown {
  if (format === "yaml") return parseYaml(content);
  return JSON.parse(content);
}

export function serializeConfig(value: unknown, format: ConfigFormat): string {
  if (format === "yaml") return stringifyYaml(value, { indent: 2 });
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function discoverConfigFile(
  dir: string,
  basename: string,
): { path: string; format: ConfigFormat } | null {
  // Try in order: config.json, config.yaml, config.yml
  const candidates = [
    { file: `${basename}.json`, format: "json" as const },
    { file: `${basename}.yaml`, format: "yaml" as const },
    { file: `${basename}.yml`, format: "yaml" as const },
  ];
  for (const { file, format } of candidates) {
    const fullPath = path.join(dir, file);
    if (fs.existsSync(fullPath)) return { path: fullPath, format };
  }
  return null;
}

/**
 * Resolve `file://` references in config values.
 *
 * When a string value starts with `file://`, the referenced file is read,
 * parsed (JSON or YAML based on extension), and recursively resolved.
 * Depth is capped at 3 to prevent unbounded recursion.
 */
export function resolveFileReferences(value: unknown, baseDir: string, depth: number = 0): unknown {
  if (depth > 3) {
    throw new Error("Config file reference depth limit exceeded (max 3)");
  }

  if (typeof value === "string" && value.startsWith("file://")) {
    const refPath = value.slice(7); // remove "file://"
    const resolved = path.resolve(baseDir, refPath);
    // Security: prevent path traversal outside baseDir
    if (!isPathWithinRoot(baseDir, resolved)) {
      throw new Error(`Config file reference escapes base directory: ${refPath}`);
    }
    const content = fs.readFileSync(resolved, "utf-8");
    const format = detectConfigFormat(resolved);
    const parsed = parseConfigFile(content, format);
    return resolveFileReferences(parsed, path.dirname(resolved), depth + 1);
  }

  if (Array.isArray(value)) {
    return value.map((item) => resolveFileReferences(item, baseDir, depth));
  }

  if (value !== null && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      result[key] = resolveFileReferences(val, baseDir, depth);
    }
    return result;
  }

  return value;
}

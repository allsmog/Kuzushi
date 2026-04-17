import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

let cached: string | null = null;

/**
 * Resolves the absolute path to the installed shinsa-plugin directory.
 * The plugin ships as a GitHub tarball without a package.json, so we can't
 * use `require.resolve("shinsa-plugin/package.json")` — walk up from this
 * module's location looking for `<anc>/node_modules/shinsa-plugin/.claude-plugin/plugin.json`.
 */
export function resolveShinsaPluginPath(): string {
  if (cached) return cached;

  let current = path.dirname(fileURLToPath(import.meta.url));
  const visited = new Set<string>();

  while (!visited.has(current)) {
    visited.add(current);
    const candidate = path.join(current, "node_modules", "shinsa-plugin");
    const manifest = path.join(candidate, ".claude-plugin", "plugin.json");
    if (existsSync(manifest)) {
      cached = candidate;
      return candidate;
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }

  throw new Error(
    "shinsa-plugin is not installed or is missing .claude-plugin/plugin.json. " +
      "Install with: pnpm add github:allsmog/shinsa-plugin",
  );
}

/** Reset the cached plugin path (for testing). */
export function resetShinsaPluginCache(): void {
  cached = null;
}

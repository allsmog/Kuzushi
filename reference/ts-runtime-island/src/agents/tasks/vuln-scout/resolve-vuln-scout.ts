import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(import.meta.url);

let cached: { type: "local"; path: string } | null = null;

/**
 * Resolves the installed @kuzushi/vuln-scout package and returns a plugin
 * entry pointing at the whitebox-pentest sub-plugin (the actual Claude Code
 * plugin directory declared in marketplace.json).
 */
export function resolveVulnScoutPlugin(): { type: "local"; path: string } {
  if (cached) return cached;

  const pkgPath = require.resolve("@kuzushi/vuln-scout/package.json");
  const repoRoot = path.dirname(pkgPath);
  const pluginDir = path.join(repoRoot, "whitebox-pentest");
  const manifest = path.join(pluginDir, ".claude-plugin", "plugin.json");

  if (!existsSync(manifest)) {
    throw new Error(
      `@kuzushi/vuln-scout is installed but missing whitebox-pentest/.claude-plugin/plugin.json at ${repoRoot}. ` +
        "Try reinstalling: pnpm install",
    );
  }

  cached = { type: "local", path: pluginDir };
  return cached;
}

/** Reset the cached plugin (for testing). */
export function resetVulnScoutPluginCache(): void {
  cached = null;
}

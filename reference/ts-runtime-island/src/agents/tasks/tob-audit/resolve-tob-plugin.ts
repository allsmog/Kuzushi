import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(import.meta.url);

/** Security-relevant plugins from the trailofbits/skills fork. */
const SECURITY_PLUGINS = [
  "fp-check",
  "variant-analysis",
  "sharp-edges",
  "insecure-defaults",
  "static-analysis",
  "differential-review",
  "audit-context-building",
  "supply-chain-risk-auditor",
  "testing-handbook-skills",
  "trailmark",
  "semgrep-rule-creator",
  "entry-point-analyzer",
];

let cached: Array<{ type: "local"; path: string }> | null = null;

/**
 * Resolves the installed @kuzushi/tob-skills package and returns plugin
 * entries for each security-relevant sub-plugin that has a valid manifest.
 */
export function resolveTobPlugins(): Array<{ type: "local"; path: string }> {
  if (cached) return cached;

  const pkgPath = require.resolve("@kuzushi/tob-skills/package.json");
  const repoRoot = path.dirname(pkgPath);
  const pluginsDir = path.join(repoRoot, "plugins");

  if (!existsSync(pluginsDir)) {
    throw new Error(
      `@kuzushi/tob-skills is installed but missing plugins/ directory at ${repoRoot}. ` +
        "Try reinstalling: pnpm install",
    );
  }

  const plugins: Array<{ type: "local"; path: string }> = [];
  for (const name of SECURITY_PLUGINS) {
    const pluginDir = path.join(pluginsDir, name);
    const manifest = path.join(pluginDir, ".claude-plugin", "plugin.json");
    if (existsSync(manifest)) {
      plugins.push({ type: "local", path: pluginDir });
    }
  }

  if (plugins.length === 0) {
    throw new Error(
      `@kuzushi/tob-skills has no valid security plugins in ${pluginsDir}. ` +
        "Try reinstalling: pnpm install",
    );
  }

  cached = plugins;
  return plugins;
}

/** Reset the cached plugins (for testing). */
export function resetTobPluginCache(): void {
  cached = null;
}

export { SECURITY_PLUGINS };

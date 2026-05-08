import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(import.meta.url);

let cached: string | null = null;

/**
 * Resolves the absolute path to the installed promptarmor-plugin Claude Code
 * plugin directory. The published package is `promptarmor-plugin` (monorepo
 * root); the actual plugin manifest lives at `plugin/.claude-plugin/plugin.json`.
 */
export function resolvePromptArmorPluginPath(): string {
  if (cached) return cached;

  const pkgPath = require.resolve("promptarmor-plugin/package.json");
  const packageRoot = path.dirname(pkgPath);
  const pluginDir = path.join(packageRoot, "plugin");

  const manifest = path.join(pluginDir, ".claude-plugin", "plugin.json");
  if (!existsSync(manifest)) {
    throw new Error(
      `promptarmor-plugin is installed but missing plugin/.claude-plugin/plugin.json at ${packageRoot}. ` +
        "Try reinstalling: pnpm install",
    );
  }

  cached = pluginDir;
  return pluginDir;
}

/** Reset the cached plugin path (for testing). */
export function resetPromptArmorPluginCache(): void {
  cached = null;
}

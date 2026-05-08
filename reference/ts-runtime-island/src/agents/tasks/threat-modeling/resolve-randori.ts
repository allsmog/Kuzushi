import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

const require = createRequire(import.meta.url);

let cached: string | null = null;

/**
 * Resolves the absolute path to the installed @kuzushi/randori-plugin directory.
 * The plugin ships as an npm dependency — no manual path configuration needed.
 */
export function resolveRandoriPluginPath(): string {
  if (cached) return cached;

  const pkgPath = require.resolve("@kuzushi/randori-plugin/package.json");
  const pluginRoot = path.dirname(pkgPath);

  const manifest = path.join(pluginRoot, ".claude-plugin", "plugin.json");
  if (!existsSync(manifest)) {
    throw new Error(
      `@kuzushi/randori-plugin is installed but missing .claude-plugin/plugin.json at ${pluginRoot}. ` +
        "Try reinstalling: pnpm install",
    );
  }

  cached = pluginRoot;
  return pluginRoot;
}

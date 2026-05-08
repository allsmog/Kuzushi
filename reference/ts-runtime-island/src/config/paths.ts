import { existsSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { discoverConfigFile } from "../config-io.js";

export const CONFIG_DIR = path.join(os.homedir(), ".kuzushi");
export const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");
const PROJECT_CONFIG_DIR = ".kuzushi";
const CONFIG_BASENAME = "config";

/** Markers that anchor the walk-up search for a project root. */
const ROOT_MARKERS = [".git", "package.json", "pyproject.toml", "Cargo.toml", "go.mod"];

export function configPath(): string {
  const discovered = discoverConfigFile(CONFIG_DIR, CONFIG_BASENAME);
  if (discovered) {
    return discovered.path;
  }
  return CONFIG_PATH;
}

export function projectConfigPath(repoRoot: string): string {
  const dir = path.join(repoRoot, PROJECT_CONFIG_DIR);
  const discovered = discoverConfigFile(dir, CONFIG_BASENAME);
  if (discovered) {
    return discovered.path;
  }
  return path.join(dir, `${CONFIG_BASENAME}.json`);
}

/**
 * Walk up from `startDir` looking for the nearest ancestor that contains a
 * `.kuzushi/config.json`. Stops at a recognized project root (the first
 * directory containing any of: `.git/`, `.kuzushi/`, `package.json`,
 * `pyproject.toml`, `Cargo.toml`) — without this, scanning a sub-tree of
 * `~/monorepo` would silently traverse into the user's home dir and pick up
 * unrelated configs.
 *
 * Returns the directory containing `.kuzushi/config.json`, or null when no
 * project-local config exists in any ancestor up to the project root.
 *
 * Why this exists: project-local config is the supported per-repo override
 * mechanism, but `kuzushi shell` from `<repo>/sub/path/` previously ignored
 * `<repo>/.kuzushi/config.json` because the lookup was strictly cwd-only.
 * Operators reasonably expect repo-rooted config to apply to subdir invocations.
 */
export function findProjectConfigRoot(startDir: string): string | null {
  let dir = path.resolve(startDir);
  // Cap iterations defensively — a normal filesystem won't have more than
  // ~30 path segments, but pathological symlink loops could otherwise infloop.
  for (let depth = 0; depth < 64; depth += 1) {
    const candidate = path.join(dir, PROJECT_CONFIG_DIR, `${CONFIG_BASENAME}.json`);
    if (existsSync(candidate)) return dir;
    // Stop once we exit the project boundary: if THIS dir contains a
    // project-root marker (`.git/`, `package.json`, etc.) but no kuzushi
    // config, ascending further would leak into unrelated parents.
    let hitProjectRoot = false;
    for (const marker of ROOT_MARKERS) {
      const markerPath = path.join(dir, marker);
      if (!existsSync(markerPath)) continue;
      try {
        // `.git` can be a file (worktree pointer) or directory; both anchor a root.
        statSync(markerPath);
        hitProjectRoot = true;
        break;
      } catch {
        /* unreadable marker — ignore */
      }
    }
    if (hitProjectRoot) return null;
    const parent = path.dirname(dir);
    if (parent === dir) return null; // filesystem root
    dir = parent;
  }
  return null;
}

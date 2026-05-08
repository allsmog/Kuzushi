/**
 * Recipe discovery — locates bundled `.kzrc.yaml` workflow scripts.
 *
 * Search order:
 *   1. `<cwd>/.kuzushi/recipes/`         — project-local overrides
 *   2. `<cwd>/recipes/`                   — repo-root recipes (this repo's default)
 *   3. `<package-root>/recipes/`          — recipes shipped with the kuzushi install
 *
 * The first existing directory wins. A recipe name is resolved by appending
 * `.kzrc.yaml` and looking for the file in that directory.
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const RECIPE_SUFFIX = ".kzrc.yaml";

function packageRecipeRoot(): string {
  // Walk up from this module to find the package root, then look for
  // recipes/ at that level. Works both from src/ (dev) and dist/ (prod).
  const here = fileURLToPath(import.meta.url);
  let dir = path.dirname(here);
  for (let i = 0; i < 8; i++) {
    if (existsSync(path.join(dir, "package.json"))) {
      return path.join(dir, "recipes");
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return "";
}

export function recipeSearchDirs(cwd: string): string[] {
  const dirs = [
    path.join(cwd, ".kuzushi", "recipes"),
    path.join(cwd, "recipes"),
    packageRecipeRoot(),
  ];
  return dirs.filter((d) => d && existsSync(d));
}

/** Resolve `<name>` to an absolute recipe file path, or undefined if not found. */
export function resolveRecipePath(name: string, cwd: string): string | undefined {
  const suffix = name.endsWith(RECIPE_SUFFIX) ? "" : RECIPE_SUFFIX;
  const fileName = `${name}${suffix}`;
  for (const dir of recipeSearchDirs(cwd)) {
    const candidate = path.join(dir, fileName);
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

export interface RecipeListing {
  name: string;
  path: string;
  description?: string;
}

/** List every recipe across the search dirs (first-win on name collision). */
export function listRecipes(cwd: string): RecipeListing[] {
  const seen = new Set<string>();
  const out: RecipeListing[] = [];
  for (const dir of recipeSearchDirs(cwd)) {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.endsWith(RECIPE_SUFFIX)) continue;
      const name = entry.slice(0, -RECIPE_SUFFIX.length);
      if (seen.has(name)) continue;
      seen.add(name);
      const abs = path.join(dir, entry);
      const result: RecipeListing = { name, path: abs };
      const desc = firstCommentLine(abs);
      if (desc) result.description = desc;
      out.push(result);
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

function firstCommentLine(file: string): string | undefined {
  try {
    const contents = readFileSync(file, "utf8");
    for (const line of contents.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed.startsWith("#")) return trimmed.replace(/^#+\s*/, "");
      if (trimmed.length > 0) return undefined;
    }
  } catch {
    /* ignore */
  }
  return undefined;
}

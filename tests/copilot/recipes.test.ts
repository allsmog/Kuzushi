import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { listRecipes, resolveRecipePath } from "../../src/copilot/recipes.js";

const tempDirs: string[] = [];

function tmpCwd(files: Record<string, string>): string {
  const root = mkdtempSync(path.join(tmpdir(), "kuzushi-recipes-"));
  tempDirs.push(root);
  for (const [rel, contents] of Object.entries(files)) {
    const abs = path.join(root, rel);
    mkdirSync(path.dirname(abs), { recursive: true });
    writeFileSync(abs, contents, "utf8");
  }
  return root;
}

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe("recipes discovery", () => {
  it("resolves recipes from <cwd>/recipes/<name>.kzrc.yaml", () => {
    const cwd = tmpCwd({
      "recipes/quick-scan.kzrc.yaml": "commands:\n  - modules\n",
    });
    const p = resolveRecipePath("quick-scan", cwd);
    expect(p).toBeDefined();
    expect(p).toContain("quick-scan.kzrc.yaml");
  });

  it("resolves recipes from .kuzushi/recipes/ (project overrides win)", () => {
    const cwd = tmpCwd({
      "recipes/foo.kzrc.yaml": "commands:\n  - shipped\n",
      ".kuzushi/recipes/foo.kzrc.yaml": "commands:\n  - override\n",
    });
    const p = resolveRecipePath("foo", cwd);
    expect(p).toContain(path.join(".kuzushi", "recipes"));
  });

  it("returns undefined for unknown recipes", () => {
    const cwd = tmpCwd({});
    expect(resolveRecipePath("ghost", cwd)).toBeUndefined();
  });

  it("listRecipes includes a description from the first comment line", () => {
    const cwd = tmpCwd({
      "recipes/test-a.kzrc.yaml": "# Hello world recipe\ncommands:\n  - modules\n",
      "recipes/test-b.kzrc.yaml": "commands:\n  - modules\n",
    });
    const recipes = listRecipes(cwd);
    const names = recipes.map((r) => r.name);
    expect(names).toContain("test-a");
    expect(names).toContain("test-b");
    expect(recipes.find((r) => r.name === "test-a")?.description).toBe("Hello world recipe");
    expect(recipes.find((r) => r.name === "test-b")?.description).toBeUndefined();
  });

  it("accepts a name with the .kzrc.yaml suffix already attached", () => {
    const cwd = tmpCwd({
      "recipes/foo.kzrc.yaml": "commands:\n",
    });
    expect(resolveRecipePath("foo.kzrc.yaml", cwd)).toBeDefined();
  });
});

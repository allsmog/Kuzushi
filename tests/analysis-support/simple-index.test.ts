import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createSimpleTextIndexProvider } from "../../src/analysis-support/simple-index.js";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function createRepo(files: Record<string, string>): string {
  const repoRoot = mkdtempSync(path.join(os.tmpdir(), "kuzushi-index-"));
  tempDirs.push(repoRoot);
  for (const [relativePath, content] of Object.entries(files)) {
    const absolutePath = path.join(repoRoot, relativePath);
    mkdirSync(path.dirname(absolutePath), { recursive: true });
    writeFileSync(absolutePath, content, "utf-8");
  }
  return repoRoot;
}

describe("SimpleTextIndexProvider", () => {
  it("looks up symbols and snippets from indexed source files", async () => {
    const repoRoot = createRepo({
      "src/app.ts": [
        "export async function loadUser(userId: string) {",
        "  return db.query(userId);",
        "}",
      ].join("\n"),
    });

    const index = await createSimpleTextIndexProvider(repoRoot);
    const matches = await index.findSymbol({
      symbol: "query",
      receiverHint: "db",
    });

    expect(matches[0]?.filePath).toBe("src/app.ts");
    expect(matches[0]?.receiverMatched).toBe(true);
    expect(await index.getSnippet("src/app.ts", 2)).toBe("return db.query(userId);");
  });

  it("returns changed files for a git diff base", async () => {
    const repoRoot = createRepo({
      "src/app.ts": "export const answer = 41;\n",
    });

    execFileSync("git", ["init"], { cwd: repoRoot });
    execFileSync("git", ["config", "user.email", "codex@example.com"], { cwd: repoRoot });
    execFileSync("git", ["config", "user.name", "Codex"], { cwd: repoRoot });
    execFileSync("git", ["add", "."], { cwd: repoRoot });
    execFileSync("git", ["commit", "-m", "init"], { cwd: repoRoot });
    writeFileSync(path.join(repoRoot, "src/app.ts"), "export const answer = 42;\n", "utf-8");

    const index = await createSimpleTextIndexProvider(repoRoot);
    const diffSlice = await index.getDiffSlice("HEAD");

    expect(diffSlice.base).toBe("HEAD");
    expect(diffSlice.changedFiles).toContain("src/app.ts");
  }, 15_000);

  it("indexes multi-language repos with many files", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 50; i++) {
      files[`src/module${i}.ts`] =
        `export function handler${i}(req: Request) { return fetch(req.url); }\n`;
    }
    for (let i = 0; i < 20; i++) {
      files[`lib/util${i}.py`] = `def process${i}(data):\n    return data.strip()\n`;
    }
    files["go/main.go"] = `package main\nfunc main() { http.ListenAndServe(":8080", nil) }\n`;

    const repoRoot = createRepo(files);
    const index = await createSimpleTextIndexProvider(repoRoot);

    // Text search across languages
    const fetchMatches = await index.searchText("fetch");
    expect(fetchMatches.length).toBeGreaterThan(0);
    expect(fetchMatches[0].filePath).toMatch(/module\d+\.ts$/);

    const pyMatches = await index.searchText("process");
    expect(pyMatches.length).toBeGreaterThan(0);

    // Symbol lookup
    const symbols = await index.findSymbol({ symbol: "handler25" });
    expect(symbols.length).toBeGreaterThan(0);
    expect(symbols[0].filePath).toBe("src/module25.ts");
  });

  it("handles empty repos gracefully", async () => {
    const repoRoot = createRepo({});
    const index = await createSimpleTextIndexProvider(repoRoot);

    const matches = await index.searchText("anything");
    expect(matches).toEqual([]);

    const symbols = await index.findSymbol({ symbol: "nothing" });
    expect(symbols).toEqual([]);
  });

  it("getDiffSlice returns empty changedFiles when no changes exist", async () => {
    const repoRoot = createRepo({
      "src/clean.ts": "export const x = 1;\n",
    });

    execFileSync("git", ["init"], { cwd: repoRoot });
    execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: repoRoot });
    execFileSync("git", ["config", "user.name", "Test"], { cwd: repoRoot });
    execFileSync("git", ["add", "."], { cwd: repoRoot });
    execFileSync("git", ["commit", "-m", "init"], { cwd: repoRoot });

    const index = await createSimpleTextIndexProvider(repoRoot);
    const diffSlice = await index.getDiffSlice("HEAD");
    expect(diffSlice.changedFiles).toHaveLength(0);
  }, 15_000);
});

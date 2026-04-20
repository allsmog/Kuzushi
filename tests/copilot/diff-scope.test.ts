import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { computeDiffScope, filterByChangedFiles } from "../../src/copilot/diff-scope.js";

function git(repo: string, args: string[]): void {
  execFileSync("git", args, { cwd: repo, stdio: ["ignore", "ignore", "ignore"] });
}

describe("diff-scope", () => {
  describe("computeDiffScope", () => {
    let repo: string;

    beforeEach(() => {
      repo = path.join(tmpdir(), `kz-diff-${Date.now()}-${Math.random().toString(36).slice(2)}`);
      mkdirSync(repo, { recursive: true });
      git(repo, ["init", "-q"]);
      git(repo, ["config", "user.email", "test@example.com"]);
      git(repo, ["config", "user.name", "test"]);
      git(repo, ["config", "commit.gpgsign", "false"]);
    });
    afterEach(() => {
      rmSync(repo, { recursive: true, force: true });
    });

    it("returns ok=false when the path isn't a git repo", () => {
      const plain = path.join(tmpdir(), `kz-notgit-${Date.now()}`);
      mkdirSync(plain, { recursive: true });
      const out = computeDiffScope(plain, "main");
      expect(out.ok).toBe(false);
      expect(out.error).toMatch(/not a git repo/);
      rmSync(plain, { recursive: true, force: true });
    });

    it("returns ok=false for an empty ref", () => {
      const out = computeDiffScope(repo, "");
      expect(out.ok).toBe(false);
      expect(out.error).toBe("empty ref");
    });

    it("lists files that differ between a past commit and HEAD", () => {
      writeFileSync(path.join(repo, "a.txt"), "one\n");
      writeFileSync(path.join(repo, "b.txt"), "two\n");
      git(repo, ["add", "."]);
      git(repo, ["commit", "-q", "-m", "initial"]);
      const initialSha = execFileSync("git", ["rev-parse", "HEAD"], {
        cwd: repo,
        encoding: "utf-8",
      }).trim();

      writeFileSync(path.join(repo, "b.txt"), "two-changed\n");
      writeFileSync(path.join(repo, "c.txt"), "three\n");
      git(repo, ["add", "."]);
      git(repo, ["commit", "-q", "-m", "change b + add c"]);

      const out = computeDiffScope(repo, initialSha);
      expect(out.ok).toBe(true);
      expect(out.changedFiles.sort()).toEqual(["b.txt", "c.txt"]);
    });

    it("returns an empty changed-file list when HEAD === ref", () => {
      writeFileSync(path.join(repo, "a.txt"), "only\n");
      git(repo, ["add", "."]);
      git(repo, ["commit", "-q", "-m", "initial"]);
      const out = computeDiffScope(repo, "HEAD");
      expect(out.ok).toBe(true);
      expect(out.changedFiles).toEqual([]);
    });

    it("returns ok=false for an unknown ref (and still doesn't throw)", () => {
      writeFileSync(path.join(repo, "a.txt"), "x\n");
      git(repo, ["add", "."]);
      git(repo, ["commit", "-q", "-m", "initial"]);
      const out = computeDiffScope(repo, "nonexistent-ref");
      expect(out.ok).toBe(false);
      expect(out.error).toBeTruthy();
    });
  });

  describe("filterByChangedFiles", () => {
    const items = [
      { id: 1, filePath: "src/a.ts" },
      { id: 2, filePath: "src/b.ts" },
      { id: 3, filePath: "src/c.ts" },
      { id: 4 }, // no filePath
    ];

    it("keeps items whose filePath is in the changed set", () => {
      const out = filterByChangedFiles(items, ["src/a.ts", "src/c.ts"]);
      expect(out.map((i) => i.id)).toEqual([1, 3]);
    });

    it("returns an empty list when changedFiles is empty", () => {
      expect(filterByChangedFiles(items, [])).toEqual([]);
    });

    it("drops items without a filePath", () => {
      const out = filterByChangedFiles(items, ["src/a.ts", "src/b.ts"]);
      expect(out.every((i) => i.filePath !== undefined)).toBe(true);
    });
  });
});

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { findProjectConfigRoot } from "../../src/config/paths.js";

describe("findProjectConfigRoot — walk-up project config discovery", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(path.join(tmpdir(), "kuzushi-paths-"));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  function touch(rel: string, contents = ""): string {
    const full = path.join(tmp, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, contents);
    return full;
  }

  it("returns null when no .kuzushi/config.json exists anywhere", () => {
    mkdirSync(path.join(tmp, "project"), { recursive: true });
    expect(findProjectConfigRoot(path.join(tmp, "project"))).toBeNull();
  });

  it("returns the dir when .kuzushi/config.json exists at startDir", () => {
    touch("project/.kuzushi/config.json", "{}");
    touch("project/.git/config", "");
    expect(findProjectConfigRoot(path.join(tmp, "project"))).toBe(path.join(tmp, "project"));
  });

  it("walks up to find .kuzushi/config.json in an ancestor", () => {
    // The headline case: kuzushi shell from <repo>/sub/dir/ should pick up
    // <repo>/.kuzushi/config.json.
    touch("project/.kuzushi/config.json", "{}");
    touch("project/.git/config", "");
    mkdirSync(path.join(tmp, "project/sub/deep"), { recursive: true });
    expect(findProjectConfigRoot(path.join(tmp, "project/sub/deep"))).toBe(
      path.join(tmp, "project"),
    );
  });

  it("stops at the first project-root marker (.git) without escaping", () => {
    // Parent has a config; child has its own .git anchoring a project boundary.
    touch("outer/.kuzushi/config.json", "{}");
    touch("outer/inner/.git/config", "");
    mkdirSync(path.join(tmp, "outer/inner/sub"), { recursive: true });
    // Looking from `outer/inner/sub` should NOT escape past `outer/inner`'s .git
    expect(findProjectConfigRoot(path.join(tmp, "outer/inner/sub"))).toBeNull();
  });

  it("stops at package.json marker", () => {
    touch("outer/.kuzushi/config.json", "{}");
    touch("outer/inner/package.json", "{}");
    mkdirSync(path.join(tmp, "outer/inner/sub"), { recursive: true });
    expect(findProjectConfigRoot(path.join(tmp, "outer/inner/sub"))).toBeNull();
  });

  it("stops at pyproject.toml marker", () => {
    touch("outer/.kuzushi/config.json", "{}");
    touch("outer/inner/pyproject.toml", "");
    mkdirSync(path.join(tmp, "outer/inner/sub"), { recursive: true });
    expect(findProjectConfigRoot(path.join(tmp, "outer/inner/sub"))).toBeNull();
  });

  it("stops at Cargo.toml marker", () => {
    touch("outer/.kuzushi/config.json", "{}");
    touch("outer/inner/Cargo.toml", "");
    mkdirSync(path.join(tmp, "outer/inner/sub"), { recursive: true });
    expect(findProjectConfigRoot(path.join(tmp, "outer/inner/sub"))).toBeNull();
  });

  it("stops at go.mod marker", () => {
    touch("outer/.kuzushi/config.json", "{}");
    touch("outer/inner/go.mod", "");
    mkdirSync(path.join(tmp, "outer/inner/sub"), { recursive: true });
    expect(findProjectConfigRoot(path.join(tmp, "outer/inner/sub"))).toBeNull();
  });

  it("returns startDir's config even when a marker also exists at startDir", () => {
    // .git AT startDir doesn't preempt the config check at startDir itself.
    touch("project/.kuzushi/config.json", "{}");
    touch("project/.git/config", "");
    expect(findProjectConfigRoot(path.join(tmp, "project"))).toBe(path.join(tmp, "project"));
  });

  it("returns null on filesystem root when no config + no markers anywhere", () => {
    // Defensive: walking from a deeply nested temp dir without config or
    // markers should terminate at the FS root and return null.
    mkdirSync(path.join(tmp, "a/b/c"), { recursive: true });
    expect(findProjectConfigRoot(path.join(tmp, "a/b/c"))).toBeNull();
  });
});

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveRepo } from "../../src/cli/shared.js";

// macOS /var is a symlink to /private/var — git always returns the
// realpath-resolved form, so normalize both sides in assertions.
const canonical = (p: string) => realpathSync(p);

describe("resolveRepo", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(path.join(tmpdir(), "kuzushi-resolve-repo-"));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("returns the absolute target path as root when not in a git repo", () => {
    const result = resolveRepo(tmp);
    expect(result.root).toBe(path.resolve(tmp));
    expect(result.name).toBe(path.basename(tmp));
    expect(result.gitRoot).toBeUndefined();
  });

  it("omits gitRoot when target equals the git toplevel", () => {
    execFileSync("git", ["init", "--quiet"], { cwd: tmp });
    const result = resolveRepo(tmp);
    expect(result.root).toBe(path.resolve(tmp));
    expect(result.gitRoot).toBeUndefined();
  });

  it("reports gitRoot separately when target is a subdirectory of the git toplevel", () => {
    execFileSync("git", ["init", "--quiet"], { cwd: tmp });
    const sub = path.join(tmp, "service-a");
    mkdirSync(sub);
    const result = resolveRepo(sub);
    expect(result.root).toBe(path.resolve(sub));
    expect(result.name).toBe("service-a");
    expect(result.gitRoot).toBeDefined();
    expect(canonical(result.gitRoot!)).toBe(canonical(tmp));
  });

  it("uses basename of the user-provided path, not the git root", () => {
    execFileSync("git", ["init", "--quiet"], { cwd: tmp });
    const sub = path.join(tmp, "teleport");
    mkdirSync(sub);
    const result = resolveRepo(sub);
    // Key behavior: name reflects operator intent, not git-repo identity.
    expect(result.name).toBe("teleport");
    expect(result.root.endsWith("teleport")).toBe(true);
  });
});

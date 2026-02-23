import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import path from "node:path";

const TMP_HOME = path.join(import.meta.dirname, ".tmp-resolve-test");
const TMP_BIN = path.join(TMP_HOME, ".kuzushi", "bin");

vi.mock("node:os", () => ({
  default: { homedir: () => TMP_HOME },
  homedir: () => TMP_HOME,
}));

// Control which binaries are "found" on PATH
let whichResults: Record<string, string | null> = {};

vi.mock("node:child_process", async () => {
  const actual = await vi.importActual<typeof import("node:child_process")>("node:child_process");
  return {
    ...actual,
    // execFileSync is used by the `which` helper in resolve.ts
    execFileSync: vi.fn((cmd: string, args: string[]) => {
      if (cmd === "which" && args?.[0]) {
        const result = whichResults[args[0]];
        if (result) return result + "\n";
        throw new Error(`not found: ${args[0]}`);
      }
      throw new Error(`unexpected call: ${cmd} ${args}`);
    }),
  };
});

const { resolveScanner } = await import("../src/scanner/resolve.js");

beforeEach(() => {
  mkdirSync(TMP_BIN, { recursive: true });
  whichResults = {};
});

afterEach(() => {
  rmSync(TMP_HOME, { recursive: true, force: true });
});

describe("resolveScanner", () => {
  it("returns opengrep from PATH if available", async () => {
    whichResults["opengrep"] = "/usr/local/bin/opengrep";
    const result = await resolveScanner();
    expect(result).toBe("/usr/local/bin/opengrep");
  });

  it("falls back to semgrep on PATH", async () => {
    whichResults["semgrep"] = "/usr/local/bin/semgrep";
    const result = await resolveScanner();
    expect(result).toBe("/usr/local/bin/semgrep");
  });

  it("prefers opengrep over semgrep on PATH", async () => {
    whichResults["opengrep"] = "/usr/local/bin/opengrep";
    whichResults["semgrep"] = "/usr/local/bin/semgrep";
    const result = await resolveScanner();
    expect(result).toBe("/usr/local/bin/opengrep");
  });

  it("returns cached binary if it exists", async () => {
    const cachedBin = path.join(TMP_BIN, "opengrep");
    writeFileSync(cachedBin, "fake-binary");
    chmodSync(cachedBin, 0o755);

    const result = await resolveScanner();
    expect(result).toBe(cachedBin);
  });
});

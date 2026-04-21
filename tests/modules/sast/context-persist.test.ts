import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  contextSnapshotPath,
  loadContextSnapshot,
  saveContextSnapshot,
} from "../../../src/modules/sast/context-persist.js";
import type { ContextSnapshot } from "../../../src/ui/state.js";

const tempDirs: string[] = [];

beforeEach(() => {
  tempDirs.length = 0;
});

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  }
});

function makeTempTarget(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-context-persist-"));
  tempDirs.push(dir);
  return dir;
}

function makeSnapshot(overrides: Partial<ContextSnapshot> = {}): ContextSnapshot {
  return {
    target: "/repo",
    timestamp: Date.now(),
    discovery: "flat",
    options: { enrichment: true, threatModel: true, scenarios: false },
    appModel: { routes: [] },
    threatModel: { threats: [] },
    ...overrides,
  };
}

describe("context-persist", () => {
  it("saves a snapshot to <target>/.kuzushi/context-snapshot.json", () => {
    const target = makeTempTarget();
    const snap = makeSnapshot();
    const ok = saveContextSnapshot(target, snap);
    expect(ok).toBe(true);
    const saved = readFileSync(contextSnapshotPath(target), "utf8");
    expect(JSON.parse(saved)).toEqual(snap);
  });

  it("creates the .kuzushi/ dir if it doesn't exist", () => {
    const target = makeTempTarget();
    // Nested: directory does not pre-exist.
    const nested = path.join(target, "subproject");
    const ok = saveContextSnapshot(nested, makeSnapshot());
    expect(ok).toBe(true);
  });

  it("loads a previously-saved snapshot (round-trip)", () => {
    const target = makeTempTarget();
    const snap = makeSnapshot({
      target: path.resolve(target),
      appModel: { routes: [{ path: "/api/x" }] },
    });
    saveContextSnapshot(target, snap);
    const loaded = loadContextSnapshot(target);
    expect(loaded).toEqual(snap);
  });

  it("returns null when no snapshot file exists", () => {
    const target = makeTempTarget();
    expect(loadContextSnapshot(target)).toBeNull();
  });

  it("returns null for a malformed JSON file (silent failure)", () => {
    const target = makeTempTarget();
    const snapshotPath = contextSnapshotPath(target);
    const dir = path.dirname(snapshotPath);
    require("node:fs").mkdirSync(dir, { recursive: true });
    writeFileSync(snapshotPath, "{not valid json}", "utf8");
    expect(loadContextSnapshot(target)).toBeNull();
  });

  it("returns null when the JSON is valid but not a ContextSnapshot shape", () => {
    const target = makeTempTarget();
    const snapshotPath = contextSnapshotPath(target);
    const dir = path.dirname(snapshotPath);
    require("node:fs").mkdirSync(dir, { recursive: true });
    writeFileSync(snapshotPath, JSON.stringify({ foo: "bar" }), "utf8");
    expect(loadContextSnapshot(target)).toBeNull();
  });

  it("saveContextSnapshot returns false on unwritable paths (no throw)", () => {
    // /dev/null/foo — writing under a non-dir should fail; verify no throw.
    const ok = saveContextSnapshot("/dev/null/impossible", makeSnapshot());
    expect(ok).toBe(false);
  });

  it("snapshot path is relative to the absolute target", () => {
    const target = makeTempTarget();
    expect(contextSnapshotPath(target)).toBe(
      path.join(target, ".kuzushi", "context-snapshot.json"),
    );
    // Relative target is resolved absolute too.
    expect(contextSnapshotPath(".")).toBe(
      path.join(process.cwd(), ".kuzushi", "context-snapshot.json"),
    );
  });

  it("process.cwd() fallback loads a snapshot when called from inside the target", () => {
    // Simulates `cd <target>; kuzushi` with no -T flag — the shell
    // startup loader needs to find the cached snapshot via cwd, not
    // just via an explicit opts.target.
    const target = makeTempTarget();
    const snap = makeSnapshot({
      target: path.resolve(target),
      appModel: { routes: [{ path: "/api/x" }] },
      threatModel: { threats: [{ id: "T1" }] },
    });
    saveContextSnapshot(target, snap);

    // The loader calls path.resolve(target) internally; passing cwd-style
    // "." from inside the target exercises the same code path as the
    // shell's `opts.target ?? process.cwd()` fallback.
    const originalCwd = process.cwd();
    try {
      process.chdir(target);
      const loaded = loadContextSnapshot(".");
      expect(loaded).toEqual(snap);
    } finally {
      process.chdir(originalCwd);
    }
  });
});

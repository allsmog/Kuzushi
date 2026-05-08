import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createScanFindingsStore,
  SqliteScanFindingsStore,
} from "../../src/bus/orchestrator/scan-findings-store.js";
import { allMigrations, runMigrations } from "../../src/migrations/index.js";
import type { Finding } from "../../src/scanners/types.js";

function makeFinding(fp: string, line = 1): Finding {
  return {
    fingerprint: fp,
    taskId: "semgrep" as Finding["taskId"],
    ruleId: "rule-x",
    filePath: "src/x.ts",
    startLine: line,
    severity: "ERROR",
    message: "test finding",
    cwe: [],
    evidence: null,
  } as unknown as Finding;
}

let db: Database.Database;
const RUN_ID = "run-test";

beforeEach(() => {
  db = new Database(":memory:");
  runMigrations(db, allMigrations);
});

afterEach(() => {
  db.close();
});

describe("SqliteScanFindingsStore", () => {
  it("starts empty", () => {
    const s = new SqliteScanFindingsStore(db, RUN_ID);
    expect(s.count()).toBe(0);
    expect(s.toArray()).toEqual([]);
    expect(s.fingerprints()).toEqual([]);
    expect([...s.iterate()]).toEqual([]);
  });

  it("preserves insertion order across add and addAll", () => {
    const s = new SqliteScanFindingsStore(db, RUN_ID);
    s.add(makeFinding("a"));
    s.addAll([makeFinding("b"), makeFinding("c")]);
    s.add(makeFinding("d"));
    expect(s.fingerprints()).toEqual(["a", "b", "c", "d"]);
  });

  it("replace() swaps buffer wholesale without retaining prior items", () => {
    const s = new SqliteScanFindingsStore(db, RUN_ID);
    s.addAll([makeFinding("a"), makeFinding("b")]);
    s.replace([makeFinding("x"), makeFinding("y"), makeFinding("z")]);
    expect(s.count()).toBe(3);
    expect(s.fingerprints()).toEqual(["x", "y", "z"]);
  });

  it("clear() resets to empty", () => {
    const s = new SqliteScanFindingsStore(db, RUN_ID);
    s.add(makeFinding("a"));
    s.clear();
    expect(s.count()).toBe(0);
    expect(s.toArray()).toEqual([]);
  });

  it("iterate() produces a fresh iterator each call", () => {
    const s = new SqliteScanFindingsStore(db, RUN_ID);
    s.addAll([makeFinding("a"), makeFinding("b")]);
    const first = [...s.iterate()].map((f) => f.fingerprint);
    const second = [...s.iterate()].map((f) => f.fingerprint);
    expect(first).toEqual(["a", "b"]);
    expect(second).toEqual(["a", "b"]);
  });

  it("toArray() returns a defensive copy", () => {
    const s = new SqliteScanFindingsStore(db, RUN_ID);
    s.add(makeFinding("a"));
    const arr = s.toArray();
    arr.push(makeFinding("rogue"));
    expect(s.count()).toBe(1);
    expect(s.fingerprints()).toEqual(["a"]);
  });

  it("replace() accepts any iterable, not just arrays", () => {
    const s = new SqliteScanFindingsStore(db, RUN_ID);
    function* gen(): Generator<Finding> {
      yield makeFinding("g1");
      yield makeFinding("g2");
    }
    s.replace(gen());
    expect(s.fingerprints()).toEqual(["g1", "g2"]);
  });

  it("isolates rows by run_id — concurrent runs don't see each other", () => {
    const a = new SqliteScanFindingsStore(db, "run-A");
    const b = new SqliteScanFindingsStore(db, "run-B");
    a.addAll([makeFinding("a1"), makeFinding("a2")]);
    b.add(makeFinding("b1"));
    expect(a.fingerprints()).toEqual(["a1", "a2"]);
    expect(b.fingerprints()).toEqual(["b1"]);
    a.clear();
    expect(a.count()).toBe(0);
    expect(b.count()).toBe(1);
  });

  it("resumes ordinal numbering when a fresh store is opened against existing rows", () => {
    const first = new SqliteScanFindingsStore(db, RUN_ID);
    first.addAll([makeFinding("a"), makeFinding("b")]);

    const resumed = new SqliteScanFindingsStore(db, RUN_ID);
    resumed.add(makeFinding("c"));
    expect(resumed.fingerprints()).toEqual(["a", "b", "c"]);
  });
});

describe("createScanFindingsStore", () => {
  it("defaults to in-memory when no backend is specified", () => {
    const s = createScanFindingsStore();
    s.add(makeFinding("a"));
    expect(s.fingerprints()).toEqual(["a"]);
    // SQLite store would have written rows; in-memory leaves the table empty.
    const rows = db.prepare("SELECT COUNT(*) AS n FROM scan_findings").get() as { n: number };
    expect(rows.n).toBe(0);
  });

  it("returns a SqliteScanFindingsStore when backend is sqlite + db + runId provided", () => {
    const s = createScanFindingsStore({ backend: "sqlite", db, runId: RUN_ID });
    s.addAll([makeFinding("a"), makeFinding("b")]);
    const rows = db
      .prepare("SELECT COUNT(*) AS n FROM scan_findings WHERE run_id = ?")
      .get(RUN_ID) as { n: number };
    expect(rows.n).toBe(2);
  });

  it("falls back to in-memory when backend is sqlite but db/runId are missing", () => {
    const s = createScanFindingsStore({ backend: "sqlite" });
    s.add(makeFinding("a"));
    expect(s.fingerprints()).toEqual(["a"]);
  });
});

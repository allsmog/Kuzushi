import { describe, expect, it } from "vitest";
import { InMemoryScanFindingsStore } from "../../src/bus/orchestrator/scan-findings-store.js";
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

describe("InMemoryScanFindingsStore", () => {
  it("starts empty", () => {
    const s = new InMemoryScanFindingsStore();
    expect(s.count()).toBe(0);
    expect(s.toArray()).toEqual([]);
    expect(s.fingerprints()).toEqual([]);
    expect([...s.iterate()]).toEqual([]);
  });

  it("seeds from an initial iterable", () => {
    const s = new InMemoryScanFindingsStore([makeFinding("a"), makeFinding("b")]);
    expect(s.count()).toBe(2);
    expect(s.fingerprints()).toEqual(["a", "b"]);
  });

  it("preserves insertion order across add and addAll", () => {
    const s = new InMemoryScanFindingsStore();
    s.add(makeFinding("a"));
    s.addAll([makeFinding("b"), makeFinding("c")]);
    s.add(makeFinding("d"));
    expect(s.fingerprints()).toEqual(["a", "b", "c", "d"]);
  });

  it("replace() swaps buffer wholesale without retaining prior items", () => {
    const s = new InMemoryScanFindingsStore([makeFinding("a"), makeFinding("b")]);
    s.replace([makeFinding("x"), makeFinding("y"), makeFinding("z")]);
    expect(s.count()).toBe(3);
    expect(s.fingerprints()).toEqual(["x", "y", "z"]);
  });

  it("clear() resets to empty", () => {
    const s = new InMemoryScanFindingsStore([makeFinding("a")]);
    s.clear();
    expect(s.count()).toBe(0);
    expect(s.toArray()).toEqual([]);
  });

  it("iterate() produces a fresh iterator each call", () => {
    const s = new InMemoryScanFindingsStore([makeFinding("a"), makeFinding("b")]);
    const first = [...s.iterate()].map((f) => f.fingerprint);
    const second = [...s.iterate()].map((f) => f.fingerprint);
    expect(first).toEqual(["a", "b"]);
    expect(second).toEqual(["a", "b"]);
  });

  it("toArray() returns a defensive copy", () => {
    const s = new InMemoryScanFindingsStore([makeFinding("a")]);
    const arr = s.toArray();
    arr.push(makeFinding("rogue"));
    expect(s.count()).toBe(1);
    expect(s.fingerprints()).toEqual(["a"]);
  });

  it("replace() accepts any iterable, not just arrays", () => {
    const s = new InMemoryScanFindingsStore();
    function* gen(): Generator<Finding> {
      yield makeFinding("g1");
      yield makeFinding("g2");
    }
    s.replace(gen());
    expect(s.fingerprints()).toEqual(["g1", "g2"]);
  });
});

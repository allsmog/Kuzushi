import { describe, expect, it } from "vitest";
import { attachCiStream } from "../../src/ui/ci-stream.js";
import { createUIStore } from "../../src/ui/state.js";

function captureLines(): { lines: string[]; write: (l: string) => void } {
  const lines: string[] = [];
  return {
    lines,
    write: (l) => {
      lines.push(l);
    },
  };
}

describe("attachCiStream", () => {
  it("emits no lines until running mode", () => {
    const store = createUIStore();
    const cap = captureLines();
    const unsub = attachCiStream(store, { write: cap.write });
    store.update({ repoName: "acme-api" });
    expect(cap.lines).toEqual([]);
    unsub();
  });

  it("announces scan start, phase, stage, and summary", () => {
    const store = createUIStore();
    const cap = captureLines();
    const unsub = attachCiStream(store, { write: cap.write });

    store.update({ mode: "running", repoName: "acme-api" });
    store.initStages([{ id: "scan", label: "Scan" }]);
    store.update({ phase: "scanning" });
    store.activateStage("scan");
    store.completeStage("scan");
    store.update({ phase: "done", mode: "summary" });

    const joined = cap.lines.join("\n");
    expect(joined).toContain("scan: acme-api started");
    expect(joined).toContain("phase:");
    expect(joined).toContain("stage: scan → active");
    expect(joined).toContain("stage: scan → done");
    unsub();
  });

  it("deduplicates finding events per fingerprint", () => {
    const store = createUIStore();
    const cap = captureLines();
    const unsub = attachCiStream(store, { write: cap.write });
    store.update({ mode: "running", repoName: "repo" });

    for (let i = 0; i < 3; i++) {
      store.addResult({
        kind: "triage",
        verdict: "tp",
        confidence: 0.9,
        costUsd: 0.01,
        fingerprint: "abc",
        index: 1,
        total: 1,
      });
    }
    const findingLines = cap.lines.filter((l) => l.includes("finding:"));
    expect(findingLines).toHaveLength(1);
    unsub();
  });

  it("emitFindings=false suppresses per-finding lines", () => {
    const store = createUIStore();
    const cap = captureLines();
    const unsub = attachCiStream(store, { write: cap.write, emitFindings: false });
    store.update({ mode: "running", repoName: "repo" });
    store.addResult({
      kind: "triage",
      verdict: "tp",
      fingerprint: "xyz",
      index: 1,
      total: 1,
    });
    expect(cap.lines.filter((l) => l.includes("finding:"))).toHaveLength(0);
    unsub();
  });
});

import type { DagNodeImpl, OutputKind } from "../src/agents/types.js";
import type { Finding, TaskId } from "../src/scanners/types.js";
import type { TriageResult } from "../src/types.js";

/**
 * Deterministic 32-bit PRNG (xorshift). Gives every benchmark the same inputs
 * across runs so deltas reflect code changes, not input noise.
 */
export function prng(seed: number): () => number {
  let s = seed | 0 || 0x9e3779b9;
  return () => {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return (s >>> 0) / 0xffffffff;
  };
}

const CWE_POOL = [
  ["CWE-79"],
  ["CWE-89"],
  ["CWE-22"],
  ["CWE-78"],
  ["CWE-502"],
  ["CWE-798"],
  ["CWE-918"],
  ["CWE-611"],
  ["CWE-352"],
  ["CWE-287"],
  // Overlap pairs — common causes of cluster merges
  ["CWE-79", "CWE-80"],
  ["CWE-89", "CWE-564"],
  ["CWE-78", "CWE-77"],
  // Empty CWE — forced singleton path
  [],
];

const RULE_IDS = [
  "semgrep.xss",
  "semgrep.sqli",
  "semgrep.path-traversal",
  "semgrep.cmd-inject",
  "codeql.deserialization",
  "codeql.hardcoded-secret",
  "codeql.ssrf",
  "agentic.auth-bypass",
  "agentic.race-condition",
];

const SEVERITIES = ["low", "medium", "high", "critical"];

/** Build N synthetic findings with controlled location collisions so dedup actually merges. */
export function makeFindings(count: number, seed = 42): Finding[] {
  const rng = prng(seed);
  // ~30% of findings land on a shared (file,line) to force clustering work.
  const collisionSlots = Math.max(1, Math.floor(count / 30));
  const out: Finding[] = [];
  for (let i = 0; i < count; i++) {
    const hot = rng() < 0.3;
    const file = hot ? `src/hot_${Math.floor(rng() * collisionSlots)}.ts` : `src/file_${i}.ts`;
    const line = hot ? (Math.floor(rng() * 20) + 1) * 10 : i * 3 + 1;
    const cwe = CWE_POOL[Math.floor(rng() * CWE_POOL.length)];
    const ruleId = RULE_IDS[Math.floor(rng() * RULE_IDS.length)];
    const severity = SEVERITIES[Math.floor(rng() * SEVERITIES.length)];
    out.push({
      taskId: "semgrep" as TaskId,
      fingerprint: `fp-${i}`,
      ruleId,
      filePath: file,
      startLine: line,
      severity,
      message: `Synthetic finding ${i} at ${file}:${line}`,
      evidence: `user_input flows to ${ruleId.split(".")[1]} at line ${line}`,
      scannerConfidence: "medium",
      subcategory: [],
      likelihood: "likely",
      impact: "medium",
      cwe: [...cwe],
      score: rng() * 10,
    });
  }
  return out;
}

/** Build a 100-task DAG with realistic fan-in/fan-out. */
export function makeTaskRegistrySnapshot(
  count: number,
  seed = 7,
): {
  ids: string[];
  tasks: DagNodeImpl[];
} {
  const rng = prng(seed);
  const tasks: DagNodeImpl[] = [];
  const ids: string[] = [];
  for (let i = 0; i < count; i++) {
    const id = `task-${i}`;
    ids.push(id);
    // First 10 are roots (no deps). Others depend on 1-3 earlier tasks.
    const dependsOn: string[] = [];
    if (i >= 10) {
      const depCount = 1 + Math.floor(rng() * 3);
      for (let d = 0; d < depCount; d++) {
        const parent = Math.floor(rng() * i);
        const pid = `task-${parent}`;
        if (!dependsOn.includes(pid)) dependsOn.push(pid);
      }
    }
    tasks.push({
      id,
      displayName: id,
      outputKind: "findings" as OutputKind,
      dependsOn,
      async run(): Promise<unknown> {
        return {};
      },
    });
  }
  return { ids, tasks };
}

/** Minimal triage result for store batch benchmarks. */
export function makeTriageResults(count: number, seed = 9): TriageResult[] {
  const rng = prng(seed);
  // DB CHECK constraint only allows these three verdicts.
  const verdicts: TriageResult["verdict"][] = ["tp", "fp", "needs_review"];
  const out: TriageResult[] = [];
  for (let i = 0; i < count; i++) {
    out.push({
      fingerprint: `fp-${i}`,
      verdict: verdicts[Math.floor(rng() * verdicts.length)],
      confidence: rng(),
      rationale: `rationale ${i}`,
      verificationSteps: [`check ${i}`, `probe ${i}`],
      fixPatch: null,
    });
  }
  return out;
}

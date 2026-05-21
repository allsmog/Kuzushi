import type { OutputKind } from "../src/modules/types.js";

interface DagNodeImpl {
  id: string;
  displayName: string;
  outputKind: OutputKind;
  dependsOn: string[];
  run(): Promise<unknown>;
}

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
    tasks.push({
      id,
      displayName: id,
      outputKind: "findings" as OutputKind,
      dependsOn: dependenciesForTask(i, rng),
      async run(): Promise<unknown> {
        return {};
      },
    });
  }
  return { ids, tasks };
}

function dependenciesForTask(index: number, rng: () => number): string[] {
  if (index < 10) return [];

  const dependsOn: string[] = [];
  const depCount = 1 + Math.floor(rng() * 3);
  for (let d = 0; d < depCount; d++) {
    const pid = `task-${Math.floor(rng() * index)}`;
    if (!dependsOn.includes(pid)) dependsOn.push(pid);
  }
  return dependsOn;
}

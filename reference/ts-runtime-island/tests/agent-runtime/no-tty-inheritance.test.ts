import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const REPO_ROOT = path.resolve(__dirname, "../..");

const RUNTIME_PATHS = [
  "src/agent-runtime",
  "src/agents",
  "src/bus/workers",
  "src/fuzz",
  "src/modules",
  "src/scanners",
  "src/strategies",
];

const TS_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".mjs", ".cjs"]);

function* walk(dir: string): Generator<string> {
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      yield* walk(full);
      continue;
    }
    if (stat.isFile() && TS_EXTENSIONS.has(path.extname(full))) {
      yield full;
    }
  }
}

function runtimeSourceFiles(): string[] {
  return RUNTIME_PATHS.flatMap((rel) => Array.from(walk(path.join(REPO_ROOT, rel))));
}

function rel(file: string): string {
  return path.relative(REPO_ROOT, file);
}

describe("runtime subprocess stdio", () => {
  it("does not hand module/runtime subprocesses inherited TTY descriptors", () => {
    const offenders: string[] = [];

    for (const file of runtimeSourceFiles()) {
      const source = readFileSync(file, "utf8");
      const inheritedStdio =
        /stdio\s*:\s*["']inherit["']/.test(source) ||
        /stdio\s*:\s*\[[^\]]*["']inherit["'][^\]]*\]/s.test(source);
      if (inheritedStdio) offenders.push(rel(file));
    }

    expect(offenders).toEqual([]);
  });
});

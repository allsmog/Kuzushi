import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  groundCallableTargets,
  groundNamedHints,
} from "../../../../src/agents/tasks/taint-analysis/grounding.js";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function createRepo(files: Record<string, string>): string {
  const repoRoot = mkdtempSync(path.join(os.tmpdir(), "kuzushi-grounding-"));
  tempDirs.push(repoRoot);
  for (const [relativePath, content] of Object.entries(files)) {
    const absolutePath = path.join(repoRoot, relativePath);
    mkdirSync(path.dirname(absolutePath), { recursive: true });
    writeFileSync(absolutePath, content, "utf-8");
  }
  return repoRoot;
}

describe("taint-analysis grounding", () => {
  it("verifies callables that are present with plausible arg positions", async () => {
    const repoRoot = createRepo({
      "src/db.ts": [
        "export function runQuery(queryText: string, params: unknown[]) {",
        "  return db.query(queryText, params);",
        "}",
      ].join("\n"),
    });

    const [grounded] = await groundCallableTargets(repoRoot, [
      {
        callable: "query",
        receiverHint: "db",
        argIndex: 1,
      },
    ]);

    expect(grounded.grounding.status).toBe("verified");
    expect(grounded.grounding.matchCount).toBeGreaterThan(0);
    expect(grounded.grounding.evidence[0]?.filePath).toBe("src/db.ts");
  });

  it("drops callables that do not appear in the repo", async () => {
    const repoRoot = createRepo({
      "src/app.ts": "console.log('hello');\n",
    });

    const [grounded] = await groundCallableTargets(repoRoot, [
      {
        callable: "definitelyMissingSink",
        receiverHint: "db",
        argIndex: 0,
      },
    ]);

    expect(grounded.grounding.status).toBe("invalid");
    expect(grounded.grounding.reasons).toContain("callable_not_found_in_repo");
  });

  it("grounds named hints from repo text", async () => {
    const repoRoot = createRepo({
      "src/sql.ts": 'builder.Raw("select 1")\n',
    });

    const [present, missing] = await groundNamedHints(repoRoot, ["Raw", "Sprintf"]);
    expect(present.grounding.status).toBe("verified");
    expect(missing.grounding.status).toBe("invalid");
  });
});

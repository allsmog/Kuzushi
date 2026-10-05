import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { findingsFromScan, scanCost, targetIdentity } from "./recall-run-receipt.mjs";

function sarif(count, runId = "current") {
  return {
    properties: {
      kuzushiScanRunId: runId,
      kuzushiExport: {
        completeness: "all",
        totalCount: count,
        includedCount: count,
      },
    },
    runs: [
      {
        tool: { driver: { name: "fixture" } },
        results: Array.from({ length: count }, (_, i) => ({
          fingerprints: { "kuzushi/v1": `fp-${i}` },
          ruleId: "CWE-78",
          level: "error",
          message: { text: "issue" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: `src/file%20${i}.c` },
                region: { startLine: 10 },
              },
            },
          ],
        })),
      },
    ],
  };
}

test("exact-run complete export keeps 501 rows and a later empty run stays empty", () => {
  const scan = { ok: true, status: "completed", runId: "current" };
  assert.equal(findingsFromScan(scan, sarif(501)).findings.length, 501);
  assert.equal(findingsFromScan(scan, sarif(0)).findings.length, 0);
  assert.throws(() => findingsFromScan(scan, sarif(1, "previous")), /exact scan/);
  const truncated = sarif(500);
  truncated.properties.kuzushiExport.totalCount = 501;
  assert.throws(() => findingsFromScan(scan, truncated), /incomplete/);
  assert.throws(() => findingsFromScan({ ...scan, ok: false }, sarif(1)), /successfully/);
});

test("exact, estimated, unavailable and measured-zero spend remain distinct", () => {
  assert.equal(scanCost({ costUsd: 1.25, providerSpendUnresolved: false }).exactUsd, 1.25);
  assert.equal(scanCost({ costUsd: 0, providerSpendUnresolved: false }).exactUsd, 0);
  assert.equal(
    scanCost({ costUsd: 0, estimatedCostUsd: 2, providerSpendUnresolved: true }).exactUsd,
    null,
  );
  assert.equal(scanCost({}).exactUsd, null);
});

test("official provenance rejects a dirty, unpinned or mismatched target", () => {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-recall-"));
  const target = join(root, "target");
  try {
    execFileSync("git", ["init", "-q", target]);
    writeFileSync(join(target, "source.c"), "original");
    execFileSync("git", ["-C", target, "add", "source.c"]);
    execFileSync("git", [
      "-C",
      target,
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "commit",
      "-qm",
      "fixture",
    ]);
    const commit = execFileSync("git", ["-C", target, "rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim();
    const oracle = join(root, "oracle.json");
    const scope = join(root, "scope.txt");
    writeFileSync(oracle, JSON.stringify({ commit }));
    writeFileSync(scope, "source.c\n");
    assert.equal(targetIdentity(target, oracle, scope).commit, commit);
    writeFileSync(join(target, "source.c"), "patched");
    assert.throws(() => targetIdentity(target, oracle, scope));
    writeFileSync(oracle, "{}");
    assert.throws(() => targetIdentity(target, oracle, scope), /pinned/);
    writeFileSync(oracle, JSON.stringify({ commit: "0".repeat(40) }));
    assert.throws(() => targetIdentity(target, oracle, scope), /does not match/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

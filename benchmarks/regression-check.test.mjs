import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixtureMetrics = JSON.parse(
  readFileSync(resolve(repoRoot, "benchmarks/fixtures/mock-govwa-metrics.json"), "utf8"),
);
const fixtureSarif = JSON.parse(
  readFileSync(resolve(repoRoot, "benchmarks/fixtures/mock-govwa.sarif.json"), "utf8"),
);
const emptyScanSarif = JSON.parse(
  readFileSync(resolve(repoRoot, "benchmarks/fixtures/rust-empty-scan.sarif.json"), "utf8"),
);
const govwaDataset = resolve(repoRoot, "benchmarks/govwa");
const provenancePath = resolve(repoRoot, "benchmarks/baseline-provenance.json");
const realModelWorkflow = readFileSync(
  resolve(repoRoot, ".github/workflows/benchmark-real-model.yml"),
  "utf8",
);
const deterministicWorkflow = readFileSync(
  resolve(repoRoot, ".github/workflows/benchmark-regression.yml"),
  "utf8",
);
const freezeBaselineSource = readFileSync(
  resolve(repoRoot, "benchmarks/freeze-baseline.ts"),
  "utf8",
);

test("missing baseline fails closed", () => {
  const fixture = regressionFixture();
  const run = invokeRegression(fixture);
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /Baseline not found/);
});

test("regression exits nonzero", () => {
  const fixture = regressionFixture();
  writeBaseline(fixture.baseline, fixtureMetrics);
  writeJson(fixture.results, { ...fixtureMetrics, precision: 0, recall: 0, f1: 0 });
  const run = invokeRegression(fixture);
  assert.notEqual(run.status, 0);
  assert.match(run.stdout, /REGRESSION DETECTED/);
});

test("equal metrics pass", () => {
  const fixture = regressionFixture();
  writeBaseline(fixture.baseline, fixtureMetrics);
  const run = invokeRegression(fixture);
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /All datasets passed/);
});

test("code revisions are observational and remain comparable", () => {
  const fixture = regressionFixture();
  const before = structuredClone(fixtureMetrics);
  before.provenance.observed.kuzushiRevision = "revision-before";
  writeBaseline(fixture.baseline, before);
  const run = invokeRegression(fixture);
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /revision-before -> 775a4134f2cb/);
});

test("comparable provenance mismatches fail with the differing field", async (t) => {
  const cases = [
    ["datasetDigest", "datasetDigest", `sha256:${"2".repeat(64)}`],
    ["modelIdentity", "modelIdentity", "different-model"],
    ["scanConfigDigest", "scanConfigDigest", `sha256:${"3".repeat(64)}`],
    ["harnessDigest", "harnessDigest", `sha256:${"4".repeat(64)}`],
  ];
  for (const [name, field, value] of cases) {
    await t.test(name, () => {
      const fixture = regressionFixture();
      writeBaseline(fixture.baseline, fixtureMetrics);
      const changed = structuredClone(fixtureMetrics);
      changed.provenance.comparable[field] = value;
      writeJson(fixture.results, changed);
      const run = invokeRegression(fixture, ["--update-baseline"]);
      assert.notEqual(run.status, 0);
      assert.match(run.stderr, new RegExp(field));
      assert.match(run.stderr, /intentional new baseline/);
    });
  }
});

test("scoreboard derives deterministic mode and revisions only from artifacts", () => {
  const fixture = regressionFixture();
  const run = invokeScoreboard(fixture);
  assert.equal(run.status, 0, run.stderr);
  const scoreboard = readFileSync(fixture.scoreboard, "utf8");
  assert.match(scoreboard, /Mode: `deterministic-fixture`/);
  assert.match(scoreboard, /Code revisions: `775a4134f2cb/);
  assert.match(scoreboard, /Runtime config hashes: `not recorded \(synthetic fixture\)`/);
  assert.match(scoreboard, /Observed model calls: `0` \(audit complete; models: none\)/);
  assert.doesNotMatch(scoreboard, /real LLM run/);

  const contradiction = invokeScoreboard(fixture, ["--mock"]);
  assert.notEqual(contradiction.status, 0);
  assert.match(contradiction.stderr, /Unknown option '--mock'/);
});

test("scoreboard rejects malformed, duplicate, and mixed-provenance results", async (t) => {
  const cases = [
    ["duplicate", (fixture) => fixture.results],
    [
      "mixed mode",
      (fixture) => {
        const second = join(fixture.root, "second.json");
        const changed = secondDatasetMetrics("Second");
        changed.provenance.mode = "real-model";
        writeJson(second, changed);
        return second;
      },
    ],
    [
      "malformed",
      (fixture) => {
        const second = join(fixture.root, "malformed.json");
        writeJson(second, { dataset: "broken" });
        return second;
      },
    ],
  ];
  for (const [name, secondPath] of cases) {
    await t.test(name, () => {
      const fixture = regressionFixture();
      const second = secondPath(fixture);
      const run = invokeScoreboard(fixture, [], [fixture.results, second]);
      assert.notEqual(run.status, 0);
    });
  }
});

test("scoreboard rejects invalid dataset costs before publication", async (t) => {
  for (const [name, literal] of [
    ["negative", "-1"],
    ["non-finite", "1e400"],
  ]) {
    await t.test(name, () => {
      const fixture = regressionFixture();
      writeMetricsWithRawCost(fixture.results, literal);
      const run = invokeScoreboard(fixture);

      assert.notEqual(run.status, 0);
      assert.match(run.stderr, /Malformed benchmark metrics/);
      assert.equal(existsSync(fixture.scoreboard), false);
    });
  }
});

test("scoreboard rejects finite cost overflow before publication", () => {
  const fixture = regressionFixture();
  const first = { ...fixtureMetrics, costUsd: Number.MAX_VALUE };
  const second = { ...secondDatasetMetrics("Second"), costUsd: Number.MAX_VALUE };
  const secondPath = join(fixture.root, "second.json");
  writeJson(fixture.results, first);
  writeJson(secondPath, second);

  const run = invokeScoreboard(fixture, [], [fixture.results, secondPath]);

  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /scoreboard aggregate cost overflowed/);
  assert.equal(existsSync(fixture.scoreboard), false);
});

test("harness scores every run, exact duplicates once, and unmatched local findings as FP", () => {
  const fixture = invokeHarness(fixtureSarif, govwaDataset);
  assert.equal(fixture.run.status, 0, fixture.run.stderr);
  assert.deepEqual(readJson(fixture.output), fixtureMetrics);
  assert.match(fixture.run.stdout, /SARIF runs: 2/);
  assert.match(fixture.run.stdout, /Scored findings: 7/);
  assert.equal(fixtureMetrics.tp, 1, "later-run TP must be scored");
  assert.equal(fixtureMetrics.fp, 6, "off-corpus local finding must reduce precision");
  assert.equal(fixtureMetrics.perCwe["CWE-999"].fp, 1);
});

test("minimum-distance matching does not let an earlier nearby truth steal an exact site", () => {
  const dataset = miniDataset([
    groundTruth("vulnerable-nearby", 10, true),
    groundTruth("safe-exact", 12, false),
    groundTruth("vulnerable-exact", 20, true),
  ]);
  const sarif = miniSarif([miniResult("first", 12), miniResult("second", 20)], 0);
  const fixture = harnessFixture(dataset, sarif, ["--line-tolerance", "5"]);
  assert.equal(fixture.run.status, 0, fixture.run.stderr);
  const metrics = readJson(fixture.output);
  assert.deepEqual(
    { tp: metrics.tp, fp: metrics.fp, fn: metrics.fn, tn: metrics.tn },
    { tp: 1, fp: 1, fn: 1, tn: 0 },
  );
});

test("strict CWE matching rejects unknown and wrong classes but accepts equivalent spellings", async (t) => {
  const dataset = miniDataset([groundTruth("vulnerable", 20, true)]);
  const cases = [
    ["unknown", "fixture-unknown", [], { tp: 0, fp: 1, fn: 1 }],
    ["wrong", "CWE-079-fixture", ["CWE-079"], { tp: 0, fp: 1, fn: 1 }],
    ["equivalent", "rule-89", ["cwe_89"], { tp: 1, fp: 0, fn: 0 }],
  ];
  for (const [name, ruleId, tags, expected] of cases) {
    await t.test(name, () => {
      const sarif = miniSarif([miniResultForRule(name, 20, ruleId)], 0);
      sarif.runs[0].tool.driver.rules = [{ id: ruleId, properties: { tags } }];
      const fixture = harnessFixture(dataset, sarif);
      assert.equal(fixture.run.status, 0, fixture.run.stderr);
      const metrics = readJson(fixture.output);
      assert.deepEqual({ tp: metrics.tp, fp: metrics.fp, fn: metrics.fn }, expected);
    });
  }
});

test("Rust-shaped empty scan SARIF scores all vulnerable truths as false negatives", () => {
  const dataset = miniDataset([
    groundTruth("vulnerable", 20, true),
    groundTruth("safe", 30, false),
  ]);
  const fixture = harnessFixture(dataset, emptyScanSarif);
  assert.equal(fixture.run.status, 0, fixture.run.stderr);
  const metrics = readJson(fixture.output);
  assert.deepEqual(
    { tp: metrics.tp, fp: metrics.fp, fn: metrics.fn, tn: metrics.tn },
    { tp: 0, fp: 0, fn: 1, tn: 1 },
  );
  assert.deepEqual(
    { precision: metrics.precision, recall: metrics.recall, f1: metrics.f1 },
    { precision: 0, recall: 0, f1: 0 },
  );
  assert.equal(metrics.spend.runId, "scan-empty");
});

test("SARIF with runs empty still fails closed", () => {
  const malformed = structuredClone(emptyScanSarif);
  malformed.runs = [];
  const fixture = harnessFixture(miniDataset([groundTruth("vulnerable", 20, true)]), malformed);
  assert.notEqual(fixture.run.status, 0);
  assert.match(fixture.run.stderr, /No runs found/);
});

test("equal-distance matching has a stable tie-break independent of ground-truth order", () => {
  const entries = [groundTruth("safe", 12, false), groundTruth("vulnerable", 10, true)];
  const sarif = miniSarif([miniResult("equidistant", 11)], 0);
  const first = harnessFixture(miniDataset(entries), sarif, ["--line-tolerance", "5"]);
  const second = harnessFixture(miniDataset([...entries].reverse()), sarif, [
    "--line-tolerance",
    "5",
  ]);
  assert.equal(first.run.status, 0, first.run.stderr);
  assert.equal(second.run.status, 0, second.run.stderr);
  assert.deepEqual(
    scoringProjection(readJson(first.output)),
    scoringProjection(readJson(second.output)),
  );
  assert.equal(readJson(first.output).tp, 1);
});

test("nonzero aggregate spend reaches metrics", () => {
  const sarif = structuredClone(fixtureSarif);
  sarif.properties.kuzushiBenchmark.aggregateSpend = {
    runId: "scan-paid-fixture",
    totalCostUsd: 1.25,
    source: "deterministic-fixture",
    models: [],
    llmCallCount: 0,
    llmAuditComplete: true,
  };
  const fixture = invokeHarness(sarif, govwaDataset);
  assert.equal(fixture.run.status, 0, fixture.run.stderr);
  const metrics = readJson(fixture.output);
  assert.equal(metrics.costUsd, 1.25);
  assert.deepEqual(metrics.spend, {
    measured: true,
    runId: "scan-paid-fixture",
    source: "deterministic-fixture",
    models: [],
    llmCallCount: 0,
    llmAuditComplete: true,
  });
});

test("missing, legacy, and duplicate spend locations fail closed", async (t) => {
  const cases = [
    ["missing root aggregate", missingRootSpend(), /missing canonical root benchmark spend/],
    ["legacy per-run total", legacyRunSpend(), /per-run summary\.totalCostUsd/],
    ["duplicate run aggregate", duplicateRunSpend(), /aggregateSpend must exist only/],
  ];
  for (const [name, sarif, expected] of cases) {
    await t.test(name, () => {
      const fixture = invokeHarness(sarif, govwaDataset);
      assert.notEqual(fixture.run.status, 0);
      assert.match(fixture.run.stderr, expected);
    });
  }
});

test("malformed local results and conflicting stable identities fail closed", async (t) => {
  const cases = [
    [
      "missing location",
      sarifWithMalformedResult({ ruleId: "bad", message: { text: "bad" } }),
      /no scoreable local location/,
    ],
    [
      "missing rule",
      sarifWithMalformedResult({ message: { text: "bad" }, locations: [localLocation(1)] }),
      /nonempty ruleId/,
    ],
    ["conflicting fingerprint", sarifWithConflictingFingerprint(), /reuse stable identity/],
  ];
  for (const [name, sarif, expected] of cases) {
    await t.test(name, () => {
      const fixture = invokeHarness(sarif, govwaDataset);
      assert.notEqual(fixture.run.status, 0);
      assert.match(fixture.run.stderr, expected);
    });
  }
});

test("invalid line tolerances exit nonzero", async (t) => {
  for (const value of ["NaN", "-1", "1.5", "Infinity", "101", "1e2", ""]) {
    await t.test(JSON.stringify(value), () => {
      const toleranceArgs = value.startsWith("-")
        ? [`--line-tolerance=${value}`]
        : ["--line-tolerance", value];
      const fixture = invokeHarness(fixtureSarif, govwaDataset, toleranceArgs);
      assert.notEqual(fixture.run.status, 0);
      assert.match(fixture.run.stderr, /Invalid line tolerance/);
    });
  }
});

test("harness requires provenance and rejects a contradictory scan config", () => {
  const missing = invokeHarnessWithoutProvenance(fixtureSarif, govwaDataset);
  assert.notEqual(missing.run.status, 0);

  const contradictory = invokeHarness(fixtureSarif, govwaDataset, ["--config", "{}"]);
  assert.notEqual(contradictory.run.status, 0);
  assert.match(contradictory.run.stderr, /contradicts the scanConfig/);
});

test("live harness runs require an exact supported config before scan startup", async (t) => {
  const dataset = miniDataset([groundTruth("vulnerable", 20, true)]);
  const missing = invokeHarnessRun(dataset);
  assert.notEqual(missing.run.status, 0);
  assert.match(missing.run.stderr, /--run requires an explicit --config/);

  const cases = [
    ["unknown key", '{"tasks":"semgrep","ignored":true}', /unsupported scan config keys/],
    ["wrong declaration", '{"tasks":"agentic-sast"}', /contradicts the scanConfig/],
    ["non-string value", '{"tasks":["semgrep"]}', /tasks must be a nonempty/],
  ];
  for (const [name, config, expected] of cases) {
    await t.test(name, () => {
      const fixture = invokeHarnessRun(dataset, ["--config", config]);
      assert.notEqual(fixture.run.status, 0);
      assert.match(fixture.run.stderr, expected);
    });
  }
});

test("live benchmark checkout proof binds the clean declared corpus", async (t) => {
  await t.test("accepts the declared clean checkout", () => {
    const fixture = datasetCheckoutFixture();
    const run = invokeDatasetCheckoutProof(fixture.datasetPath);
    assert.equal(run.status, 0, run.stderr);
    assert.equal(run.stdout.trim(), fixture.revision);
  });

  await t.test("rejects a different origin", () => {
    const fixture = datasetCheckoutFixture();
    runGit(fixture.repo, ["remote", "set-url", "origin", "https://example.test/wrong.git"]);
    const run = invokeDatasetCheckoutProof(fixture.datasetPath);
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /does not match declared repoUrl/);
  });

  await t.test("rejects a different HEAD", () => {
    const fixture = datasetCheckoutFixture();
    writeFileSync(join(fixture.repo, "second.txt"), "second\n");
    runGit(fixture.repo, ["add", "second.txt"]);
    runGit(fixture.repo, ["commit", "-m", "second"]);
    const run = invokeDatasetCheckoutProof(fixture.datasetPath);
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /does not match declared repoRef/);
  });

  await t.test("rejects dirty source", () => {
    const fixture = datasetCheckoutFixture();
    writeFileSync(join(fixture.repo, "untracked.txt"), "dirty\n");
    const run = invokeDatasetCheckoutProof(fixture.datasetPath);
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /checkout is dirty/);
  });

  await t.test("rejects movable version tags even when they resolve to HEAD", () => {
    const fixture = datasetCheckoutFixture();
    runGit(fixture.repo, ["tag", "v1.0.0"]);
    const datasetFile = join(fixture.datasetPath, "ground-truth.json");
    writeJson(datasetFile, { ...readJson(datasetFile), repoRef: "v1.0.0" });
    const run = invokeDatasetCheckoutProof(fixture.datasetPath);
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /immutable full commit digest/);
  });

  await t.test("rejects assume-unchanged before it can hide altered bytes", () => {
    const fixture = datasetCheckoutFixture();
    runGit(fixture.repo, ["update-index", "--assume-unchanged", "source.ts"]);
    writeFileSync(join(fixture.repo, "source.ts"), "export const value = 2;\n");
    const run = invokeDatasetCheckoutProof(fixture.datasetPath);
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /non-default index flags/);
  });

  await t.test("rejects skip-worktree and sparse checkouts", () => {
    const skipped = datasetCheckoutFixture();
    runGit(skipped.repo, ["update-index", "--skip-worktree", "source.ts"]);
    rmSync(join(skipped.repo, "source.ts"));
    const skippedRun = invokeDatasetCheckoutProof(skipped.datasetPath);
    assert.notEqual(skippedRun.status, 0);
    assert.match(skippedRun.stderr, /non-default index flags/);

    const sparse = datasetCheckoutFixture();
    runGit(sparse.repo, ["sparse-checkout", "init", "--cone"]);
    const sparseRun = invokeDatasetCheckoutProof(sparse.datasetPath);
    assert.notEqual(sparseRun.status, 0);
    assert.match(sparseRun.stderr, /must not use sparse checkout/);
  });

  await t.test("rejects tracked submodules instead of trusting their nested indexes", () => {
    const fixture = datasetCheckoutFixture();
    const nested = join(fixture.root, "nested-source");
    mkdirSync(nested);
    runGit(nested, ["init", "--quiet"]);
    runGit(nested, ["config", "user.email", "benchmark@example.test"]);
    runGit(nested, ["config", "user.name", "Benchmark Test"]);
    writeFileSync(join(nested, "nested.ts"), "export const nested = true;\n");
    runGit(nested, ["add", "nested.ts"]);
    runGit(nested, ["commit", "--quiet", "-m", "nested fixture"]);
    runGit(fixture.repo, [
      "-c",
      "protocol.file.allow=always",
      "submodule",
      "add",
      "--quiet",
      nested,
      "vendor/nested",
    ]);
    runGit(fixture.repo, ["commit", "--quiet", "-am", "add nested corpus"]);
    const revision = runGit(fixture.repo, ["rev-parse", "HEAD"]).stdout.trim();
    const datasetFile = join(fixture.datasetPath, "ground-truth.json");
    writeJson(datasetFile, { ...readJson(datasetFile), repoRef: revision });

    const run = invokeDatasetCheckoutProof(fixture.datasetPath);
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /must not contain tracked Git submodules/);
  });

  await t.test("rejects ignored corpus material and allows only post-scan Kuzushi state", () => {
    const fixture = datasetCheckoutFixture();
    writeFileSync(join(fixture.repo, ".gitignore"), "ignored.log\n.kuzushi/\n");
    runGit(fixture.repo, ["add", ".gitignore"]);
    runGit(fixture.repo, ["commit", "--quiet", "-m", "ignore policy"]);
    const revision = runGit(fixture.repo, ["rev-parse", "HEAD"]).stdout.trim();
    const datasetFile = join(fixture.datasetPath, "ground-truth.json");
    writeJson(datasetFile, { ...readJson(datasetFile), repoRef: revision });

    writeFileSync(join(fixture.repo, "ignored.log"), "not canonical\n");
    const ignoredRun = invokeDatasetCheckoutProof(fixture.datasetPath);
    assert.notEqual(ignoredRun.status, 0);
    assert.match(ignoredRun.stderr, /ignored untracked content/);
    rmSync(join(fixture.repo, "ignored.log"));

    mkdirSync(join(fixture.repo, ".kuzushi"));
    writeFileSync(join(fixture.repo, ".kuzushi", "run.json"), "{}\n");
    const postScanRun = invokeDatasetCheckoutProof(fixture.datasetPath, true);
    assert.equal(postScanRun.status, 0, postScanRun.stderr);
  });

  await t.test("rejects a symlinked checkout", () => {
    const fixture = datasetCheckoutFixture();
    const actual = join(fixture.root, "actual-repo");
    renameSync(fixture.repo, actual);
    symlinkSync(actual, fixture.repo, "dir");
    const run = invokeDatasetCheckoutProof(fixture.datasetPath);
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /non-symlink directory/);
  });

  await t.test("rejects a nested checkout path", () => {
    const fixture = nestedDatasetCheckoutFixture();
    const run = invokeDatasetCheckoutProof(fixture.datasetPath);
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /must be the Git worktree root/);
  });
});

test("live scans run against an immutable materialized commit corpus", async (t) => {
  await t.test("checkout mutation cannot change the scan target bytes", () => {
    const fixture = datasetCheckoutFixture();
    const run = invokeMaterializedCorpus(fixture.datasetPath, "mutate-checkout");
    assert.equal(run.status, 0, run.stderr);
    const observed = JSON.parse(run.stdout);
    assert.equal(observed.bytes, "export const value = 1;\n");
    assert.equal(observed.rootMode, 0o555);
    assert.equal(observed.sourceMode, 0o444);
    assert.notEqual(observed.root, fixture.repo);
    assert.equal(existsSync(observed.root), false, "private corpus must be removed after callback");
    assert.equal(readFileSync(join(fixture.repo, "source.ts"), "utf8"), observed.bytes);
  });

  await t.test("allows generated state only under .kuzushi", () => {
    const fixture = datasetCheckoutFixture();
    const run = invokeMaterializedCorpus(fixture.datasetPath, "generate-state");
    assert.equal(run.status, 0, run.stderr);
    assert.equal(existsSync(JSON.parse(run.stdout).root), false);
  });

  await t.test("preserves executable intent without leaving source writable", () => {
    const fixture = datasetCheckoutFixture();
    chmodSync(join(fixture.repo, "source.ts"), 0o755);
    commitFixtureChange(fixture, "make fixture executable");
    const run = invokeMaterializedCorpus(fixture.datasetPath, "observe");
    assert.equal(run.status, 0, run.stderr);
    assert.equal(JSON.parse(run.stdout).sourceMode, 0o555);
  });

  await t.test("supports an internal symlink and snapshots it without following", () => {
    const fixture = datasetCheckoutFixture();
    symlinkSync("source.ts", join(fixture.repo, "alias.ts"));
    commitFixtureChange(fixture, "add internal symlink");
    const run = invokeMaterializedCorpus(fixture.datasetPath, "observe-alias");
    assert.equal(run.status, 0, run.stderr);
    assert.equal(JSON.parse(run.stdout).bytes, "export const value = 1;\n");
  });

  await t.test("supports an empty declared tree through the same batch protocol", () => {
    const fixture = datasetCheckoutFixture();
    rmSync(join(fixture.repo, "source.ts"));
    commitFixtureChange(fixture, "empty fixture tree");
    const run = invokeMaterializedCorpus(fixture.datasetPath, "observe-empty");
    assert.equal(run.status, 0, run.stderr);
    assert.equal(existsSync(JSON.parse(run.stdout).root), false);
  });

  await t.test("detects a materialized source mutation", () => {
    const fixture = datasetCheckoutFixture();
    const run = invokeMaterializedCorpus(fixture.datasetPath, "mutate-materialized");
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /source changed during the scan: source\.ts/);
  });

  await t.test("tracked .kuzushi entries cannot be hidden by generated state", () => {
    const fixture = datasetCheckoutFixture();
    mkdirSync(join(fixture.repo, ".kuzushi"));
    writeFileSync(join(fixture.repo, ".kuzushi", "tracked.json"), "{}\n");
    commitFixtureChange(fixture, "track benchmark state");
    const run = invokeMaterializedCorpus(fixture.datasetPath, "hide-tracked-state");
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /source changed during the scan: \.kuzushi\/tracked\.json/);
  });

  await t.test("rejects a direct escaping symlink", () => {
    const fixture = datasetCheckoutFixture();
    writeFileSync(join(fixture.datasetPath, "outside.ts"), "outside\n");
    symlinkSync("../outside.ts", join(fixture.repo, "escape.ts"));
    commitFixtureChange(fixture, "add escaping symlink");
    const run = invokeMaterializedCorpus(fixture.datasetPath, "observe");
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /symlink escape\.ts escapes the materialized corpus/);
  });

  await t.test("rejects a chained symlink that resolves outside", () => {
    const fixture = datasetCheckoutFixture();
    mkdirSync(join(fixture.repo, "sub"));
    symlinkSync("..", join(fixture.repo, "sub", "link"));
    symlinkSync("sub/link/..", join(fixture.repo, "escape.ts"));
    commitFixtureChange(fixture, "add chained escape");
    const run = invokeMaterializedCorpus(fixture.datasetPath, "observe");
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /symlink escape\.ts resolves outside the materialized corpus/);
  });

  await t.test("rejects a blob above the materialization budget before reading it", () => {
    const fixture = datasetCheckoutFixture();
    const oversized = join(fixture.repo, "oversized.bin");
    writeFileSync(oversized, "");
    truncateSync(oversized, 64 * 1024 * 1024 + 1);
    commitFixtureChange(fixture, "add oversized blob");
    const run = invokeMaterializedCorpus(fixture.datasetPath, "observe");
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /blob exceeds 67108864 bytes/);
  });
});

test("scan config argument builder adds no undeclared default task", () => {
  const run = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "--input-type=module",
      "--eval",
      "import {scanConfigArgs} from './benchmarks/benchmark-scan-config.ts'; " +
        "process.stdout.write(JSON.stringify(scanConfigArgs({mode:'standard'})));",
    ],
    { cwd: repoRoot, encoding: "utf8" },
  );
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), ["--mode", "standard"]);
});

test("ground-truth validation rejects malformed or ambiguous corpora", async (t) => {
  const entry = groundTruth("vulnerable", 20, true);
  const cases = [
    ["duplicate id", miniDataset([entry, { ...entry }]), /duplicate id/],
    ["traversal", miniDataset([{ ...entry, file: "../secret.ts" }]), /traversal/],
    ["absolute path", miniDataset([{ ...entry, file: "/tmp/secret.ts" }]), /relative path/],
    ["zero line", miniDataset([{ ...entry, line: 0 }]), /integer from 1/],
    ["noncanonical CWE", miniDataset([{ ...entry, cwe: "cwe-89" }]), /canonical CWE/],
    ["string boolean", miniDataset([{ ...entry, isVulnerable: "true" }]), /must be a boolean/],
    ["unknown entry field", miniDataset([{ ...entry, typo: true }]), /unknown fields: typo/],
    ["missing revision", { ...miniDataset([entry]), repoRef: undefined }, /repoRef/],
    [
      "mutable branch revision",
      { ...miniDataset([entry]), repoUrl: "https://example.test/repo", repoRef: "main" },
      /immutable full commit digest/,
    ],
    [
      "movable version tag",
      { ...miniDataset([entry]), repoUrl: "https://example.test/repo", repoRef: "v17.1.1" },
      /immutable full commit digest/,
    ],
    ["empty entries", miniDataset([]), /must contain 1/],
    ["untrusted URL scheme", { ...miniDataset([entry]), repoUrl: "file:///tmp/repo" }, /https:/],
  ];
  for (const [name, dataset, expected] of cases) {
    await t.test(name, () => {
      const fixture = harnessFixture(dataset, fixtureSarif);
      assert.notEqual(fixture.run.status, 0);
      assert.match(fixture.run.stderr, expected);
    });
  }
});

test("ground-truth loading rejects oversized and symlinked documents", async (t) => {
  await t.test("oversized", () => {
    const dataset = miniDataset([
      { ...groundTruth("large", 1, true), category: "x".repeat(4 * 1024 * 1024) },
    ]);
    const fixture = harnessFixture(dataset, fixtureSarif);
    assert.notEqual(fixture.run.status, 0);
    assert.match(fixture.run.stderr, /exceeds .* bytes/);
  });
  await t.test("symlink", () => {
    const root = mkdtempSync(join(tmpdir(), "kuzushi-harness-symlink-"));
    const datasetPath = join(root, "dataset");
    mkdirSync(datasetPath);
    const real = join(root, "real-ground-truth.json");
    writeJson(real, miniDataset([groundTruth("linked", 1, true)]));
    symlinkSync(real, join(datasetPath, "ground-truth.json"));
    const fixture = invokeHarness(fixtureSarif, datasetPath);
    assert.notEqual(fixture.run.status, 0);
    assert.match(fixture.run.stderr, /regular non-symlink file/);
  });
});

test("SARIF loading is no-follow and bounded by bytes, runs, results, and strings", async (t) => {
  await t.test("symlink", () => {
    const root = mkdtempSync(join(tmpdir(), "kuzushi-sarif-symlink-"));
    const real = join(root, "real.sarif.json");
    const linked = join(root, "linked.sarif.json");
    writeJson(real, fixtureSarif);
    symlinkSync(real, linked);
    const fixture = invokeHarnessPath(linked, govwaDataset);
    assert.notEqual(fixture.run.status, 0);
    assert.match(fixture.run.stderr, /regular non-symlink file/);
  });

  await t.test("byte limit", () => {
    const root = mkdtempSync(join(tmpdir(), "kuzushi-sarif-large-"));
    const path = join(root, "large.sarif.json");
    writeFileSync(path, "{}");
    truncateSync(path, 32 * 1024 * 1024 + 1);
    const fixture = invokeHarnessPath(path, govwaDataset);
    assert.notEqual(fixture.run.status, 0);
    assert.match(fixture.run.stderr, /SARIF exceeds/);
  });

  await t.test("run limit", () => {
    const sarif = structuredClone(fixtureSarif);
    sarif.runs = Array.from({ length: 129 }, () => structuredClone(sarif.runs[0]));
    const fixture = invokeHarness(sarif, govwaDataset);
    assert.notEqual(fixture.run.status, 0);
    assert.match(fixture.run.stderr, /more than 128 runs/);
  });

  await t.test("result limit", () => {
    const sarif = structuredClone(fixtureSarif);
    sarif.runs = [sarif.runs[0]];
    sarif.runs[0].results = Array.from({ length: 20_001 }, () => miniResult("bounded", 1));
    const fixture = invokeHarness(sarif, govwaDataset);
    assert.notEqual(fixture.run.status, 0);
    assert.match(fixture.run.stderr, /more than 20000 results/);
  });

  await t.test("known string limit", () => {
    const sarif = structuredClone(fixtureSarif);
    sarif.runs[0].results[0].message.text = "x".repeat(32 * 1024 + 1);
    const fixture = invokeHarness(sarif, govwaDataset);
    assert.notEqual(fixture.run.status, 0);
    assert.match(fixture.run.stderr, /message\.text exceeds 32768 bytes/);
  });
});

test("candidate generation indexes disjoint findings instead of crossing both sets", () => {
  const run = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "--input-type=module",
      "--eval",
      "import {matchFindings} from './benchmarks/benchmark-matching.ts';" +
        "const n=15000;" +
        "const truths=Array.from({length:n},(_,i)=>({id:String(i),file:`truth/${i}.ts`,line:1,cwe:'CWE-089',isVulnerable:true}));" +
        "const findings=Array.from({length:n},(_,i)=>({identity:String(i),file:`finding/${i}.ts`,line:1,endLine:1,ruleId:'cwe-89',cwes:['CWE-089'],result:{ruleId:'cwe-89',message:{text:'x'}}}));" +
        "const result=matchFindings(truths,findings,10);" +
        "process.stdout.write(`${result.matches.length}:${result.unmatched.length}`);",
    ],
    { cwd: repoRoot, encoding: "utf8", timeout: 10_000 },
  );
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.stdout, "15000:15000");
});

test("dense compatible matching fails at the deterministic residual-work budget", () => {
  const run = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "--input-type=module",
      "--eval",
      "import {matchFindings} from './benchmarks/benchmark-matching.ts';" +
        "const n=400;" +
        "const truths=Array.from({length:n},(_,i)=>({id:String(i),file:'same.ts',line:1,cwe:'CWE-089',isVulnerable:true}));" +
        "const findings=Array.from({length:n},(_,i)=>({identity:String(i),file:'same.ts',line:1,endLine:1,ruleId:'cwe-89',cwes:['CWE-089'],result:{ruleId:'cwe-89',message:{text:'x'}}}));" +
        "try{matchFindings(truths,findings,0);process.stdout.write('unexpected-success')}" +
        "catch(error){process.stdout.write(error instanceof Error?error.message:String(error))}",
    ],
    { cwd: repoRoot, encoding: "utf8", timeout: 10_000 },
  );
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /exceeds 2000000 residual edge visits/);
});

test("real-model provenance rejects imported SARIF before reading benchmark inputs", () => {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-provenance-mode-"));
  const realProvenance = writeProvenance(root, {
    executionMode: "real-model",
    modelIdentity: "anthropic:test-model",
  });
  const missingDataset = join(root, "dataset-that-does-not-exist");
  const fixture = invokeHarness("{not valid JSON", missingDataset, [], realProvenance);

  assert.notEqual(fixture.run.status, 0);
  assert.match(fixture.run.stderr, /real-model provenance requires --run/);
  assert.match(fixture.run.stderr, /--sarif is deterministic-fixture-only/);
  assert.equal(existsSync(fixture.output), false);
});

test("execution receipts enforce declared model-call evidence", async (t) => {
  const deterministic = JSON.parse(readFileSync(provenancePath, "utf8"));
  const real = {
    ...deterministic,
    executionMode: "real-model",
    modelIdentity: "anthropic:test-model",
  };
  const accepted = invokeExecutionEvidence(real, executionReceipt(canonicalReceipt()));
  assert.equal(accepted.status, 0, accepted.stderr);

  for (const [name, declaration, receipt, expected] of invalidExecutionReceiptCases(
    real,
    deterministic,
  )) {
    await t.test(name, () => {
      const run = invokeExecutionEvidence(declaration, executionReceipt(receipt));
      assert.notEqual(run.status, 0);
      assert.match(run.stderr, expected);
    });
  }
});

test("provenance rejects unsupported declared scan config fields", () => {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-provenance-config-"));
  const provenance = writeProvenance(root, { scanConfig: { tasks: "semgrep", ignored: true } });
  const fixture = invokeHarness(fixtureSarif, govwaDataset, [], provenance);
  assert.notEqual(fixture.run.status, 0);
  assert.match(fixture.run.stderr, /unsupported scan config keys: ignored/);
});

test("explicit update creates a missing baseline from result provenance", () => {
  const fixture = regressionFixture();
  const run = invokeRegression(fixture, ["--update-baseline"]);
  assert.equal(run.status, 0, run.stderr);
  const baseline = JSON.parse(readFileSync(fixture.baseline, "utf8"));
  assert.equal(baseline.schemaVersion, 2);
  assert.deepEqual(baseline.datasets.GoVWA, fixtureMetrics);
});

test("malformed baseline exits nonzero", () => {
  const fixture = regressionFixture();
  writeJson(fixture.baseline, { updatedAt: "now", datasets: [] });
  const run = invokeRegression(fixture);
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /Malformed benchmark baseline/);
});

test("negative aggregate metrics fail closed", () => {
  const fixture = regressionFixture();
  writeBaseline(fixture.baseline, fixtureMetrics);
  writeJson(fixture.results, { ...fixtureMetrics, costUsd: -1 });
  const run = invokeRegression(fixture);
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /Malformed benchmark metrics/);
});

test("metrics without a spend receipt fail closed", () => {
  const fixture = regressionFixture();
  writeBaseline(fixture.baseline, fixtureMetrics);
  const malformed = structuredClone(fixtureMetrics);
  delete malformed.spend;
  writeJson(fixture.results, malformed);
  const run = invokeRegression(fixture);
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /Malformed benchmark metrics/);
});

test("cost regression from an honest zero baseline fails without TP improvement", () => {
  const fixture = regressionFixture();
  writeBaseline(fixture.baseline, fixtureMetrics);
  const paid = structuredClone(fixtureMetrics);
  paid.costUsd = 0.25;
  paid.spend = {
    measured: true,
    runId: "scan-paid",
    source: "deterministic-fixture",
    models: [],
    llmCallCount: 0,
    llmAuditComplete: true,
  };
  paid.provenance.observed.runId = "scan-paid";
  paid.provenance.observed.spendSource = "deterministic-fixture";
  writeJson(fixture.results, paid);
  const run = invokeRegression(fixture);
  assert.notEqual(run.status, 0);
  assert.match(run.stdout, /REGRESSION DETECTED/);
  assert.match(run.stdout, /baseline was \$0/);
});

test("out-of-range nested CWE metrics fail closed", () => {
  const fixture = regressionFixture();
  writeBaseline(fixture.baseline, fixtureMetrics);
  const malformed = structuredClone(fixtureMetrics);
  malformed.perCwe["CWE-089"].recall = 1.01;
  writeJson(fixture.results, malformed);
  const run = invokeRegression(fixture);
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /Malformed benchmark metrics/);
});

test("invalid regression thresholds fail closed", async (t) => {
  const invalidThresholds = [
    ["--precision-threshold", "not-a-number"],
    ["--recall-threshold=-0.1"],
    ["--cost-threshold", "Infinity"],
    ["--cost-threshold", "11"],
  ];
  for (const threshold of invalidThresholds) {
    await t.test(threshold.join(" "), () => {
      const fixture = regressionFixture();
      writeBaseline(fixture.baseline, fixtureMetrics);
      const run = invokeRegression(fixture, threshold);
      assert.notEqual(run.status, 0);
      assert.match(run.stderr, /Invalid .* threshold/);
    });
  }
});

test("unknown dataset exits nonzero without an update flag", () => {
  const fixture = regressionFixture();
  writeBaseline(fixture.baseline, fixtureMetrics);
  const unknown = structuredClone(fixtureMetrics);
  unknown.dataset = "Unknown";
  unknown.provenance.comparable.datasetName = "Unknown";
  unknown.provenance.comparable.datasetDigest = `sha256:${"1".repeat(64)}`;
  unknown.provenance.comparable.datasetRevision = "fixture://unknown@v1";
  writeJson(fixture.results, unknown);
  const run = invokeRegression(fixture);
  assert.notEqual(run.status, 0);
  assert.match(run.stderr, /No baseline entry/);
});

test("manual real-model workflow is approval-gated, bounded, and shell-injection-safe", () => {
  assert.match(realModelWorkflow, /environment: real-model-benchmark/);
  assert.match(realModelWorkflow, /ANTHROPIC_API_KEY: \$\{\{ secrets\.ANTHROPIC_API_KEY \}\}/);
  assert.match(realModelWorkflow, /BENCHMARK_BUDGET: \$\{\{ inputs\.budget \}\}/);
  assert.match(realModelWorkflow, /type: choice/);
  assert.match(realModelWorkflow, /budget:\$budget/);
  const runBlocks = workflowRunBlocks(realModelWorkflow);
  assert.ok(runBlocks.length > 0);
  for (const block of runBlocks) assert.doesNotMatch(block, /\$\{\{\s*inputs\./);
});

test("deterministic workflow and baseline freezer use the declared harness config", () => {
  assert.match(deterministicWorkflow, /--config '\{"tasks":"semgrep"\}'/);
  assert.match(freezeBaselineSource, /canonicalScanConfig\(provenance\.scanConfig\)/);
  assert.match(freezeBaselineSource, /"--run"/);
  assert.doesNotMatch(freezeBaselineSource, /"--tasks",\s*"semgrep"/);
});

function regressionFixture() {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-regression-"));
  const fixture = {
    root,
    baseline: join(root, "baseline.json"),
    results: join(root, "metrics.json"),
    scoreboard: join(root, "SCOREBOARD.md"),
  };
  writeJson(fixture.results, fixtureMetrics);
  return fixture;
}

function invokeScoreboard(fixture, extraArgs = [], results = [fixture.results]) {
  return spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "benchmarks/scoreboard.ts",
      "--results",
      results.join(","),
      "--output",
      fixture.scoreboard,
      ...extraArgs,
    ],
    { cwd: repoRoot, encoding: "utf8" },
  );
}

function invokeRegression(fixture, extraArgs = []) {
  return spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "benchmarks/regression-check.ts",
      "--results",
      fixture.results,
      "--baseline",
      fixture.baseline,
      ...extraArgs,
    ],
    { cwd: repoRoot, encoding: "utf8" },
  );
}

function invokeHarness(sarif, dataset, extraArgs = [], provenance = provenancePath) {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-harness-"));
  const sarifPath = join(root, "input.sarif.json");
  if (typeof sarif === "string") writeFileSync(sarifPath, sarif);
  else writeJson(sarifPath, sarif);
  return invokeHarnessPath(sarifPath, dataset, extraArgs, provenance, root);
}

function invokeHarnessPath(
  sarifPath,
  dataset,
  extraArgs = [],
  provenance = provenancePath,
  root = mkdtempSync(join(tmpdir(), "kuzushi-harness-path-")),
) {
  const output = join(root, "metrics.json");
  const run = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "benchmarks/harness.ts",
      "--dataset",
      dataset,
      "--sarif",
      sarifPath,
      "--output",
      output,
      "--provenance",
      provenance,
      ...extraArgs,
    ],
    { cwd: repoRoot, encoding: "utf8" },
  );
  return { root, output, run };
}

function invokeHarnessRun(dataset, extraArgs = [], provenance = provenancePath) {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-harness-run-"));
  const datasetPath = join(root, "dataset");
  const output = join(root, "metrics.json");
  mkdirSync(datasetPath);
  writeJson(join(datasetPath, "ground-truth.json"), dataset);
  const run = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "benchmarks/harness.ts",
      "--dataset",
      datasetPath,
      "--run",
      "--output",
      output,
      "--provenance",
      provenance,
      ...extraArgs,
    ],
    { cwd: repoRoot, encoding: "utf8" },
  );
  return { root, output, run };
}

function invokeHarnessWithoutProvenance(sarif, dataset) {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-harness-no-provenance-"));
  const sarifPath = join(root, "input.sarif.json");
  const output = join(root, "metrics.json");
  writeJson(sarifPath, sarif);
  const run = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "benchmarks/harness.ts",
      "--dataset",
      dataset,
      "--sarif",
      sarifPath,
      "--output",
      output,
    ],
    { cwd: repoRoot, encoding: "utf8" },
  );
  return { root, output, run };
}

function harnessFixture(dataset, sarif, extraArgs = []) {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-harness-dataset-"));
  const datasetPath = join(root, "dataset");
  mkdirSync(datasetPath);
  writeJson(join(datasetPath, "ground-truth.json"), dataset);
  return invokeHarness(sarif, datasetPath, extraArgs);
}

function datasetCheckoutFixture() {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-benchmark-checkout-"));
  const datasetPath = join(root, "dataset");
  const repo = join(datasetPath, "repo");
  mkdirSync(repo, { recursive: true });
  runGit(repo, ["init", "--quiet"]);
  runGit(repo, ["config", "user.email", "benchmark@example.test"]);
  runGit(repo, ["config", "user.name", "Benchmark Test"]);
  writeFileSync(join(repo, "source.ts"), "export const value = 1;\n");
  runGit(repo, ["add", "source.ts"]);
  runGit(repo, ["commit", "--quiet", "-m", "fixture"]);
  runGit(repo, ["remote", "add", "origin", "https://example.test/corpus.git"]);
  const revision = runGit(repo, ["rev-parse", "HEAD"]).stdout.trim();
  writeJson(join(datasetPath, "ground-truth.json"), {
    ...miniDataset([groundTruth("fixture", 1, true)]),
    repoUrl: "https://example.test/corpus",
    repoRef: revision,
  });
  return { root, datasetPath, repo, revision };
}

function nestedDatasetCheckoutFixture() {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-benchmark-nested-checkout-"));
  const datasetPath = join(root, "dataset");
  const repo = join(datasetPath, "repo");
  mkdirSync(repo, { recursive: true });
  runGit(datasetPath, ["init", "--quiet"]);
  runGit(datasetPath, ["config", "user.email", "benchmark@example.test"]);
  runGit(datasetPath, ["config", "user.name", "Benchmark Test"]);
  runGit(datasetPath, ["remote", "add", "origin", "https://example.test/corpus.git"]);
  writeFileSync(join(repo, "source.ts"), "export const value = 1;\n");
  runGit(datasetPath, ["add", "repo/source.ts"]);
  runGit(datasetPath, ["commit", "--quiet", "-m", "fixture"]);
  const revision = runGit(datasetPath, ["rev-parse", "HEAD"]).stdout.trim();
  writeJson(join(datasetPath, "ground-truth.json"), {
    ...miniDataset([groundTruth("fixture", 1, true)]),
    repoUrl: "https://example.test/corpus",
    repoRef: revision,
  });
  return { datasetPath };
}

function invokeDatasetCheckoutProof(datasetPath, allowGeneratedKuzushiState = false) {
  return spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "--input-type=module",
      "--eval",
      "import {readFileSync} from 'node:fs'; " +
        "import {join} from 'node:path'; " +
        "import {assertDatasetCheckout} from './benchmarks/benchmark-dataset-checkout.ts'; " +
        "const root=process.env.KUZUSHI_DATASET; " +
        "const dataset=JSON.parse(readFileSync(join(root,'ground-truth.json'),'utf8')); " +
        "const options=process.env.KUZUSHI_ALLOW_STATE==='1'?{allowGeneratedKuzushiState:true}:undefined; " +
        "process.stdout.write(assertDatasetCheckout(root,dataset,options));",
    ],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        KUZUSHI_DATASET: datasetPath,
        KUZUSHI_ALLOW_STATE: allowGeneratedKuzushiState ? "1" : "0",
      },
    },
  );
}

function invokeMaterializedCorpus(datasetPath, action) {
  return spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "--input-type=module",
      "--eval",
      "import {chmodSync,lstatSync,readFileSync,mkdirSync,rmSync,writeFileSync} from 'node:fs'; " +
        "import {join} from 'node:path'; " +
        "import {withMaterializedCorpus} from './benchmarks/benchmark-materialized-corpus.ts'; " +
        "const datasetRoot=process.env.KUZUSHI_DATASET; " +
        "const sourceRoot=join(datasetRoot,'repo'); " +
        "const dataset=JSON.parse(readFileSync(join(datasetRoot,'ground-truth.json'),'utf8')); " +
        "const action=process.env.KUZUSHI_MATERIALIZED_ACTION; " +
        "const result=withMaterializedCorpus(sourceRoot,dataset.repoRef,(root)=>{ " +
        "const source=join(sourceRoot,'source.ts'); const target=join(root,'source.ts'); " +
        "if(action==='mutate-checkout'){const original=readFileSync(source); try{writeFileSync(source,'export const value = 999;\\n'); return {root,bytes:readFileSync(target,'utf8'),rootMode:lstatSync(root).mode&0o777,sourceMode:lstatSync(target).mode&0o777}}finally{writeFileSync(source,original)}} " +
        "if(action==='generate-state'){mkdirSync(join(root,'.kuzushi'),{recursive:true}); writeFileSync(join(root,'.kuzushi','run.json'),'{}\\n'); return {root}} " +
        "if(action==='mutate-materialized'){chmodSync(target,0o600); writeFileSync(target,'mutated\\n'); return {root}} " +
        "if(action==='hide-tracked-state'){const tracked=join(root,'.kuzushi','tracked.json'); rmSync(tracked); mkdirSync(tracked); return {root}} " +
        "if(action==='observe-alias'){return {root,bytes:readFileSync(join(root,'alias.ts'),'utf8')}} " +
        "if(action==='observe-empty'){return {root}} " +
        "return {root,bytes:readFileSync(target,'utf8'),sourceMode:lstatSync(target).mode&0o777}; }); " +
        "process.stdout.write(JSON.stringify(result));",
    ],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        KUZUSHI_DATASET: datasetPath,
        KUZUSHI_MATERIALIZED_ACTION: action,
      },
    },
  );
}

function commitFixtureChange(fixture, message) {
  runGit(fixture.repo, ["add", "--all"]);
  runGit(fixture.repo, ["commit", "--quiet", "-m", message]);
  const revision = runGit(fixture.repo, ["rev-parse", "HEAD"]).stdout.trim();
  const datasetFile = join(fixture.datasetPath, "ground-truth.json");
  writeJson(datasetFile, { ...readJson(datasetFile), repoRef: revision });
}

function runGit(repo, args) {
  const run = spawnSync("git", ["-C", repo, ...args], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  return run;
}

function miniDataset(entries) {
  return {
    name: "MatchingFixture",
    language: "TypeScript",
    repoUrl: "fixture://matching",
    repoRef: "fixture-v1",
    entries,
  };
}

function groundTruth(id, line, isVulnerable) {
  return { id, file: "src/app.ts", line, cwe: "CWE-089", isVulnerable };
}

function miniSarif(results, totalCostUsd) {
  return {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "fixture",
            rules: [{ id: "CWE-089-fixture", properties: { tags: ["CWE-089"] } }],
          },
        },
        results,
      },
    ],
    properties: {
      kuzushiBenchmark: {
        schemaVersion: 2,
        aggregateSpend: {
          runId: "fixture-matching",
          totalCostUsd,
          source: "deterministic-fixture",
          models: [],
          llmCallCount: 0,
          llmAuditComplete: true,
        },
      },
    },
  };
}

function canonicalReceipt() {
  return {
    source: "canonical-run-summary",
    models: ["anthropic:test-model"],
    llmCallCount: 1,
    llmAuditComplete: true,
    configHash: `sha256:${"a".repeat(64)}`,
  };
}

function executionReceipt(overrides) {
  return {
    measured: true,
    runId: "scan-real-fixture",
    ...overrides,
  };
}

function invalidExecutionReceiptCases(real, deterministic) {
  return [
    [
      "real with fixture receipt",
      real,
      {
        source: "deterministic-fixture",
        models: [],
        llmCallCount: 0,
        llmAuditComplete: true,
      },
      /canonical-run-summary/,
    ],
    ["deterministic with canonical receipt", deterministic, canonicalReceipt(), /zero model calls/],
    [
      "zero calls",
      real,
      { ...canonicalReceipt(), models: [], llmCallCount: 0 },
      /observed model call/,
    ],
    [
      "incomplete audit",
      real,
      { ...canonicalReceipt(), llmAuditComplete: false },
      /complete audit/,
    ],
    [
      "wrong model",
      real,
      { ...canonicalReceipt(), models: ["anthropic:other"] },
      /does not match the observed model set/,
    ],
    [
      "multiple models",
      real,
      { ...canonicalReceipt(), models: ["anthropic:other", "anthropic:test-model"] },
      /does not match the observed model set/,
    ],
  ];
}

function invokeExecutionEvidence(declaration, receipt) {
  const evidence = JSON.stringify({ declaration, receipt });
  return spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "--input-type=module",
      "--eval",
      "import {assertExecutionMatchesDeclaration} from './benchmarks/benchmark-execution-evidence.ts'; " +
        "const input=JSON.parse(process.env.KUZUSHI_EXECUTION_EVIDENCE); " +
        "assertExecutionMatchesDeclaration(input.declaration,input.receipt);",
    ],
    {
      cwd: repoRoot,
      encoding: "utf8",
      env: { ...process.env, KUZUSHI_EXECUTION_EVIDENCE: evidence },
    },
  );
}

function writeProvenance(root, overrides) {
  const source = JSON.parse(readFileSync(provenancePath, "utf8"));
  const path = join(root, `provenance-${Math.random().toString(16).slice(2)}.json`);
  writeJson(path, { ...source, ...overrides });
  return path;
}

function miniResult(id, line) {
  return {
    ruleId: "CWE-089-fixture",
    message: { text: id },
    fingerprints: { "kuzushi/v1": id },
    locations: [localLocation(line)],
  };
}

function miniResultForRule(id, line, ruleId) {
  return { ...miniResult(id, line), ruleId };
}

function localLocation(line, uri = "src/app.ts") {
  return {
    physicalLocation: {
      artifactLocation: { uri },
      region: { startLine: line },
    },
  };
}

function missingRootSpend() {
  const sarif = structuredClone(fixtureSarif);
  delete sarif.properties.kuzushiBenchmark;
  return sarif;
}

function legacyRunSpend() {
  const sarif = missingRootSpend();
  sarif.runs[0].properties = { summary: { totalCostUsd: 0.5 } };
  return sarif;
}

function duplicateRunSpend() {
  const sarif = structuredClone(fixtureSarif);
  sarif.runs[0].properties = {
    kuzushiBenchmark: structuredClone(sarif.properties.kuzushiBenchmark),
  };
  return sarif;
}

function sarifWithMalformedResult(result) {
  const sarif = structuredClone(fixtureSarif);
  sarif.runs[0].results.push(result);
  return sarif;
}

function sarifWithConflictingFingerprint() {
  const sarif = structuredClone(fixtureSarif);
  sarif.runs[1].results.push({
    ruleId: "fixture",
    message: { text: "conflict" },
    fingerprints: { "kuzushi/v1": "fixture-safe-main" },
    locations: [localLocation(15, "other.go")],
  });
  return sarif;
}

function writeBaseline(path, metrics) {
  writeJson(path, {
    schemaVersion: 2,
    updatedAt: "2026-07-12T00:00:00.000Z",
    datasets: { [metrics.dataset]: metrics },
  });
}

function writeMetricsWithRawCost(path, literal) {
  const encoded = JSON.stringify({ ...fixtureMetrics, costUsd: "__RAW_COST__" }, null, 2);
  writeFileSync(path, `${encoded.replace('"__RAW_COST__"', literal)}\n`);
}

function secondDatasetMetrics(name) {
  const metrics = structuredClone(fixtureMetrics);
  metrics.dataset = name;
  metrics.provenance.comparable.datasetName = name;
  metrics.provenance.comparable.datasetDigest = `sha256:${"5".repeat(64)}`;
  metrics.provenance.comparable.datasetRevision = `fixture://${name.toLowerCase()}@v1`;
  return metrics;
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(path) {
  assert.ok(existsSync(path), `expected JSON output at ${path}`);
  return JSON.parse(readFileSync(path, "utf8"));
}

function scoringProjection(metrics) {
  const { provenance: _provenance, ...scoring } = metrics;
  return scoring;
}

function workflowRunBlocks(source) {
  const lines = source.split("\n");
  const blocks = [];
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(/^(\s*)run:\s*\|\s*$/);
    if (!match) continue;
    const baseIndent = match[1].length;
    const block = [];
    while (index + 1 < lines.length) {
      const next = lines[index + 1];
      const indent = next.match(/^\s*/)[0].length;
      if (next.trim() !== "" && indent <= baseIndent) break;
      block.push(next);
      index += 1;
    }
    blocks.push(block.join("\n"));
  }
  return blocks;
}

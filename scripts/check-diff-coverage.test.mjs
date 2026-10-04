import assert from "node:assert/strict";
import test from "node:test";
import { evaluateDiffCoverage, parseChangedRustLines, parseLcov } from "./check-diff-coverage.mjs";

test("LCOV paths and execution counts normalize into source lines", () => {
  const coverage = parseLcov(
    "SF:/repo/crates/demo/src/lib.rs\nDA:10,3\nDA:11,0\nend_of_record\n",
    "/repo",
  );

  assert.deepEqual(
    [...coverage.get("crates/demo/src/lib.rs")],
    [
      [10, 3],
      [11, 0],
    ],
  );
});

test("diff parsing records added production lines and ignores tests", () => {
  const changed = parseChangedRustLines(`
diff --git a/crates/demo/src/lib.rs b/crates/demo/src/lib.rs
+++ b/crates/demo/src/lib.rs
@@ -8,0 +9,3 @@
+one
+two
+three
diff --git a/crates/demo/src/tests.rs b/crates/demo/src/tests.rs
+++ b/crates/demo/src/tests.rs
@@ -1,0 +2,2 @@
+test one
+test two
`);

  assert.deepEqual([...changed.get("crates/demo/src/lib.rs")], [9, 10, 11]);
  assert.equal(changed.has("crates/demo/src/tests.rs"), false);
});

test("diff coverage measures only executable changed lines", () => {
  const coverage = new Map([
    [
      "crates/demo/src/lib.rs",
      new Map([
        [9, 1],
        [11, 0],
      ]),
    ],
  ]);
  const changed = new Map([["crates/demo/src/lib.rs", new Set([9, 10, 11])]]);

  assert.deepEqual(evaluateDiffCoverage(coverage, changed, 80), {
    covered: 1,
    measured: 2,
    percent: 50,
    threshold: 80,
    uncovered: ["crates/demo/src/lib.rs:11"],
  });
});

test("a documentation-only Rust diff has no fabricated coverage debt", () => {
  const result = evaluateDiffCoverage(
    new Map([["crates/demo/src/lib.rs", new Map([[9, 1]])]]),
    new Map([["crates/demo/src/lib.rs", new Set([20])]]),
  );

  assert.equal(result.measured, 0);
  assert.equal(result.percent, 100);
});

test("missing instrumentation cannot become perfect coverage", () => {
  const coverage = parseLcov("SF:crates/other/src/lib.rs\nDA:1,1\nend_of_record\n");
  const changed = parseChangedRustLines(
    "+++ b/crates/new/src/lib.rs\n@@ -0,0 +1 @@\n+fn missed() {}\n",
  );
  assert.throws(
    () => evaluateDiffCoverage(coverage, changed),
    /missing coverage.*crates\/new\/src\/lib.rs/,
  );
});

test("Git C-style paths retain spaces, control characters, quotes and UTF-8", () => {
  for (const [encoded, decoded] of [
    ['"b/crates/demo/src/space name.rs"', "crates/demo/src/space name.rs"],
    ['"b/crates/demo/src/tab\\tname.rs"', "crates/demo/src/tab\tname.rs"],
    ['"b/crates/demo/src/a\\"b.rs"', 'crates/demo/src/a"b.rs'],
    ['"b/crates/demo/src/\\303\\251.rs"', "crates/demo/src/é.rs"],
    ['"b/crates/demo/src/a\\\\b.rs"', "crates/demo/src/a\\b.rs"],
  ]) {
    const changed = parseChangedRustLines(`+++ ${encoded}\n@@ -0,0 +1 @@\n+fn changed() {}\n`);
    assert.deepEqual([...changed.keys()], [decoded]);
    assert.equal(evaluateDiffCoverage(new Map([[decoded, new Map([[1, 0]])]]), changed).percent, 0);
  }
});

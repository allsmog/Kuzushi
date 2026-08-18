import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repo = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceScript = path.join(repo, "experiments/recall-eval/scripts/score.sh");
const hasShellDependencies =
  process.platform !== "win32" &&
  spawnSync("bash", ["-lc", "command -v jq >/dev/null && command -v git >/dev/null"]).status ===
    0;

const matchReport = (costUsd) => ({
  findings_total: 1,
  hits: 1,
  misses: 0,
  precision: 1,
  recall: { exact_line: 1, pm_lines: 1, function: 1, file_only: 1 },
  cost_usd: costUsd,
  wall_seconds: 2,
});

test(
  "recall-eval summaries preserve unknown cost instead of coercing it to zero",
  { skip: !hasShellDependencies },
  () => {
    withScoreHarness(
      [
        ["unknown-slice", matchReport(null)],
        ["measured-slice", matchReport(1.25)],
      ],
      ({ summary, history }) => {
        assert.match(summary, /\| unknown-slice .* \| unknown \| 2 \|/);
        assert.match(summary, /\| measured-slice .* \| 1\.25 \| 2 \|/);
        assert.match(summary, /cost=unknown/);
        assert.doesNotMatch(summary, /cost=\$1\.25/);
        assert.match(history, /\| unknown \|/);
      },
    );
  },
);

test(
  "recall-eval summaries add only fully measured costs",
  { skip: !hasShellDependencies },
  () => {
    withScoreHarness(
      [
        ["zero-slice", matchReport(0)],
        ["paid-slice", matchReport(1.25)],
      ],
      ({ summary, history }) => {
        assert.match(summary, /\| zero-slice .* \| 0 \| 2 \|/);
        assert.match(summary, /cost=\$1\.25/);
        assert.match(history, /\| \$1\.25 \|/);
      },
    );
  },
);

function withScoreHarness(reports, assertion) {
  const directory = mkdtempSync(path.join(os.tmpdir(), "kuzushi-recall-eval-score-"));
  try {
    const script = path.join(directory, "experiments/recall-eval/scripts/score.sh");
    const reportDir = path.join(directory, "experiments/recall-eval/reports/test-run");
    mkdirSync(path.dirname(script), { recursive: true });
    mkdirSync(reportDir, { recursive: true });
    cpSync(sourceScript, script);
    chmodSync(script, 0o755);
    for (const [slice, report] of reports) {
      const sliceDir = path.join(reportDir, slice);
      mkdirSync(sliceDir, { recursive: true });
      writeFileSync(path.join(sliceDir, "match.json"), JSON.stringify(report));
    }
    assert.equal(spawnSync("git", ["init", "-q"], { cwd: directory }).status, 0);
    const result = spawnSync("bash", [script, reportDir], {
      cwd: directory,
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    assertion({
      summary: readFileSync(path.join(reportDir, "summary.md"), "utf8"),
      history: readFileSync(
        path.join(directory, "experiments/recall-eval/reports/HISTORY.md"),
        "utf8",
      ),
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

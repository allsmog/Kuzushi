import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "yaml";
import { selectQualityBase } from "./quality-interval.mjs";

const workflow = (name) =>
  parse(readFileSync(new URL(`../.github/workflows/${name}.yml`, import.meta.url), "utf8"));

function requirePromotionGate(document) {
  const promote = document.jobs["promote-latest"];
  assert.ok(promote.needs.includes("published-release-smoke"));
  assert.ok(!promote.if, "promotion must use the default success-only dependency gate");
  assert.ok(
    promote.steps.some(
      (step) => step.run === "node scripts/publish-platform-packages.mjs --promote",
    ),
  );
  assert.equal(
    document.jobs["published-release-smoke"].with.version,
    "v${{ needs.preflight.outputs.version }}",
  );
  assert.ok(document.jobs["github-release"].needs.includes("promote-latest"));
  assert.ok(!document.jobs["github-release"].if);
}

test("public-install smoke must succeed before latest promotion", () => {
  const release = workflow("release");
  requirePromotionGate(release);
  const removed = structuredClone(release);
  removed.jobs["promote-latest"].needs = ["preflight"];
  assert.throws(() => requirePromotionGate(removed));
  const bypass = structuredClone(release);
  bypass.jobs["promote-latest"].if = "always()";
  assert.throws(() => requirePromotionGate(bypass));
  const comment = structuredClone(release);
  comment.jobs["promote-latest"].steps = [
    { run: "echo skipped # node scripts/publish-platform-packages.mjs --promote" },
  ];
  assert.throws(() => requirePromotionGate(comment));
});

test("every ready PR update has Rust tests and platform runtime jobs", () => {
  const ci = workflow("ci");
  assert.ok(ci.on.pull_request.types.includes("synchronize"));
  assert.ok(Object.hasOwn(ci.on, "merge_group"));
  assert.equal(
    ci.jobs["rust-tests"].if,
    "${{ github.event_name != 'pull_request' || github.event.pull_request.draft == false }}",
  );
  assert.ok(
    ci.jobs["rust-tests"].steps.some((step) => step.run === "cargo test --workspace --locked"),
  );
  assert.deepEqual(ci.jobs["platform-runtime"].strategy.matrix.os, [
    "macos-latest",
    "windows-latest",
  ]);
});

test("quality interval selects the latest successful ancestral run, never HEAD parent", () => {
  const first = "1".repeat(40),
    failed = "2".repeat(40),
    unrelated = "3".repeat(40);
  const runs = [
    {
      id: 1,
      created_at: "2026-01-01",
      head_sha: first,
      conclusion: "success",
      head_branch: "main",
    },
    {
      id: 2,
      created_at: "2026-01-02",
      head_sha: failed,
      conclusion: "failure",
      head_branch: "main",
    },
    {
      id: 3,
      created_at: "2026-01-03",
      head_sha: unrelated,
      conclusion: "success",
      head_branch: "main",
    },
  ];
  assert.equal(selectQualityBase(runs, 4, "main", (sha) => sha !== unrelated).base, first);
  assert.throws(() => selectQualityBase([], 4, "main", () => true), /explicitly/);
  assert.throws(() => selectQualityBase(runs, 1, "other", () => true), /baseline/);
  const full = workflow("ci-full");
  for (const name of ["coverage", "mutation"]) {
    const job = full.jobs[name];
    assert.ok(job, `missing quality job: ${name}`);
    assert.ok(
      job.steps.some(
        (step) =>
          step.env?.KUZUSHI_QUALITY_BASE_REF ===
          "${{ needs.quality-gauntlet.outputs.quality-base }}",
      ),
    );
  }
});

function requireArtifactVerification(document, jobName) {
  const job = document.jobs[jobName];
  assert.ok(job && job.if !== false && job.if !== "false");
  const steps = job.steps.filter((step) => typeof step.run === "string" && step.if === undefined);
  assert.ok(
    steps.some((step) =>
      step.run
        .split("\n")
        .some((line) => /^node scripts\/verify-release-artifacts\.mjs(?:\s|$)/.test(line.trim())),
    ),
  );
}

test("artifact verification must be executable, not commented out or disabled", () => {
  const release = workflow("release");
  for (const name of ["publish-npm", "github-release"]) {
    requireArtifactVerification(release, name);
    const disabled = structuredClone(release);
    const step = disabled.jobs[name].steps.find((step) =>
      step.run?.includes("node scripts/verify-release-artifacts.mjs"),
    );
    step.if = false;
    assert.throws(() => requireArtifactVerification(disabled, name));
    delete step.if;
    step.run = `# ${step.run}`;
    assert.throws(() => requireArtifactVerification(disabled, name));
  }
});

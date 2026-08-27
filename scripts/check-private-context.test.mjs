import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  CANONICAL_WORKSPACE_IGNORE_POLICY,
  PRIVATE_CONTEXT_TERMS,
  scanRepository,
  textContextFailures,
  trackedWorkspaceStateFailure,
  workspacePolicyFailures,
} from "./check-private-context.mjs";

test("approved OpenAI and Spark Java contexts remain public", () => {
  const fixtures = [
    ["model.md", "openai-codex:gpt-5.3-codex-spark"],
    ["routes.rs", 'framework.or(Some("Spark Java"));\nspark.get("/health")'],
    ["trend.rs", "render the sparkline without dummy data"],
    [
      "model_selectors.rs",
      'const catalog = "openai-codex:gpt-5.3-codex-spark";\n| "spark" => MODEL_CHOICES.get(3)',
    ],
  ];
  for (const [file, source] of fixtures) {
    assert.deepEqual(textContextFailures(file, source), []);
  }
});

test("private names, attribution, unknown Spark context, and developer homes fail", () => {
  const forbidden = [
    "Rub" + "rik control plane",
    "C" + "DM cluster",
    "R" + "SC gateway",
    "R" + "BA appliance",
    "Pol" + "aris service",
    "Glass" + "wing harness",
    "Claude " + "My" + "thos 5",
    "Co-Authored-By: Claude " + "My" + "thos 5 <noreply@example.invalid>",
    "SPARK control plane",
    "/Users/" + "shaya" + "unnejad/vibe-code/project",
  ];
  for (const source of forbidden) {
    assert.notDeepEqual(textContextFailures("fixture.txt", source), []);
  }
});

test("privacy guard sources contain no raw private identifiers", () => {
  for (const file of [
    "scripts/check-private-context.mjs",
    "scripts/check-private-context.test.mjs",
  ]) {
    const source = readFileSync(file, "utf8").toLowerCase();
    for (const privateTerm of PRIVATE_CONTEXT_TERMS) {
      assert.equal(source.includes(privateTerm), false, `${file}: ${privateTerm}`);
    }
  }
});

test("workspace state permits operator-authored inputs but rejects generated state", () => {
  for (const file of [
    "target/.kuzushi/.gitignore",
    "target/.kuzushi/scope.toml",
    "target/.kuzushi/prompts/review.md",
    "target/.kuzushi/v3/config.toml",
  ]) {
    assert.equal(trackedWorkspaceStateFailure(file), undefined);
  }
  for (const file of [
    "target/.kuzushi/credentials.json",
    "target/.kuzushi/v3/latest",
    "target/.kuzushi/v3/objects/hash",
    "target/.kuzushi/v3/runs/run-1/run.json",
  ]) {
    assert.match(trackedWorkspaceStateFailure(file), /must not be tracked/);
  }
});

test("canonical child ignore policy preserves the three trackable surfaces", () => {
  assert.deepEqual(workspacePolicyFailures(CANONICAL_WORKSPACE_IGNORE_POLICY), []);
  assert.notDeepEqual(workspacePolicyFailures("**/.kuzushi\n"), []);

  const ignored = gitCheckIgnore("crates/kuzushi-cli/.kuzushi/v3/runs/probe/run.json");
  assert.equal(ignored.status, 0, ignored.stderr);
  for (const file of [
    "crates/kuzushi-cli/.kuzushi/scope.toml",
    "crates/kuzushi-cli/.kuzushi/prompts/review.md",
    "crates/kuzushi-cli/.kuzushi/v3/config.toml",
  ]) {
    const trackable = gitCheckIgnore(file);
    assert.equal(trackable.status, 1, `${file}: ${trackable.stderr}`);
  }
});

test("the tracked current tree passes the private-context contract", () => {
  assert.deepEqual(scanRepository(), []);
});

function gitCheckIgnore(file) {
  return spawnSync("git", ["check-ignore", "--no-index", "-q", file], {
    encoding: "utf8",
  });
}

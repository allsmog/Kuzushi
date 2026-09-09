import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
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
    ["model.md", "OpenAI Codex Spark and OpenAI Spark are public model labels"],
    ["model.md", "OpenAI OAuth GPT-5.3 Codex Spark is a public model label"],
    ["engine.md", "Apache Spark processes the public example dataset"],
    ["routes.rs", 'framework.or(Some("Spark Java"));\nspark.get("/health")'],
    ["trend.rs", "render the sparkline without dummy data"],
    ["authorization.rs", "let r" + "bac_policy = policy_for(target);"],
    ["physics.md", "linear " + "polar" + "isation remains a public term"],
    ["physics.md", "the signal is polar" + "ised before comparison"],
    ["radio.md", "C" + "DMA remains a public cellular standard"],
    [
      "crates/kuzushi-tui/src/app/settings/normalize_thinking_level/model_selectors.rs",
      'const catalog = "openai-codex:gpt-5.3-codex-spark";\n| "spark" => MODEL_CHOICES.get(3)',
    ],
  ];
  for (const [file, source] of fixtures) {
    assert.deepEqual(textContextFailures(file, source), []);
  }
});

test("model alias arrays require an approved catalog file and canonical model context", () => {
  const file = "crates/kuzushi-tui/src/app/settings/model_choices.rs";
  const model = 'id: "openai-codex:gpt-5.3-codex-spark",';
  const alias = '    "spark",';
  assert.deepEqual(textContextFailures(file, `${model}\naliases: &[\n${alias}\n],`), []);
  assert.notDeepEqual(textContextFailures(file, alias), []);
  assert.notDeepEqual(textContextFailures("unknown.rs", `${model}\n${alias}`), []);
  assert.notDeepEqual(textContextFailures(file, `${model}\n${alias} // SPARK control plane`), []);
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
    "SPARK coordinator for codex transport",
    'const model = "openai-codex:gpt-5"; // SPARK control plane',
    'const model = "openai-codex:gpt-5.3-codex-spark"; // SPARK control plane',
    "Apache Spark adapter for the SPARK control plane",
    "OpenAI Codex Spark replaced the SPARK control plane",
    "// Spark Java support\nconst SPARK_CONTROL_PLANE = true;",
    "/Users/" + "shaya" + "unnejad/vibe-code/project",
    "/Users/" + "Shaya" + "un.Ne" + "jad/Desktop/project",
    "c" + "dm_cluster",
    "R" + "SCGateway",
    "Rub" + "rikClient",
    "R" + "SC" + "GATEWAY",
    "C" + "DM" + "CLUSTER",
    "RUB" + "RIKCLIENT",
    "rub" + "rikclient",
    "my" + "thosagent",
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

test("working-tree source deletions do not crash the context scan", (t) => {
  const root = contextScanFixture(t);
  unlinkSync(path.join(root, "obsolete.rs"));
  assert.deepEqual(scanRepository(root), []);
});

test("deleting the required policy still fails the context scan", (t) => {
  const root = contextScanFixture(t);
  unlinkSync(path.join(root, "crates/kuzushi-cli/.kuzushi/.gitignore"));
  assert.match(scanRepository(root).join("\n"), /canonical child ignore policy must be tracked/);
});

test("source deletions do not exempt other tracked private content", (t) => {
  const root = contextScanFixture(t);
  unlinkSync(path.join(root, "obsolete.rs"));
  writeFileSync(path.join(root, "current.rs"), `${PRIVATE_CONTEXT_TERMS[0]} internal context\n`);
  assert.match(scanRepository(root).join("\n"), /current\.rs:1:/);
});

function contextScanFixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), "kuzushi-context-scan-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const policy = "crates/kuzushi-cli/.kuzushi/.gitignore";
  mkdirSync(path.dirname(path.join(root, policy)), { recursive: true });
  writeFileSync(path.join(root, policy), CANONICAL_WORKSPACE_IGNORE_POLICY);
  writeFileSync(path.join(root, "obsolete.rs"), "// retired source\n");
  writeFileSync(path.join(root, "current.rs"), "// current source\n");
  execFileSync("git", ["-C", root, "init", "--quiet"]);
  execFileSync("git", ["-C", root, "add", "--force", "--", policy, "obsolete.rs", "current.rs"]);
  return root;
}

function gitCheckIgnore(file) {
  return spawnSync("git", ["check-ignore", "--no-index", "-q", file], {
    encoding: "utf8",
  });
}

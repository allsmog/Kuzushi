import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import {
  actionlintImageFailures,
  callGraphActionPinFailures,
  candidateWorkflowFailures,
  hostedOnlyCandidateJobs,
  hostedOnlyPublisherJobs,
  platformPublisherFailures,
  publishedSmokeWorkflowFailures,
  publisherWorkflowFailures,
  releaseCrossBuilds,
  releaseNativeBuildPlatforms,
  selfHostedMacLabels,
  selfHostedMatrixRunsOn,
} from "./release-workflow-contract.mjs";

const candidate = workflow("release-candidate.yml");
const publisher = workflow("release.yml");
const fullCi = workflow("ci-full.yml");
const publishedSmoke = workflow("published-release-smoke.yml");
const platformPublisher = readFileSync(
  new URL("./publish-platform-packages.mjs", import.meta.url),
  "utf8",
);

test("release candidate is nonpublishing and identity-bound", () => {
  assert.deepEqual(candidateWorkflowFailures(candidate), []);
  assert.deepEqual(publisherWorkflowFailures(publisher), []);
});

test("release candidate refuses lost identity and publishing authority", () => {
  const withoutIdentity = candidate.replace(
    "expected_sha must equal the caller commit",
    "sha checked",
  );
  const withCredential = `${candidate}\nNPM_TOKEN`;

  assert.match(candidateWorkflowFailures(withoutIdentity).join("\n"), /expected_sha/);
  assert.match(candidateWorkflowFailures(withCredential).join("\n"), /must not contain NPM_TOKEN/);
});

test("release matrix requires every exact native runner", () => {
  const missingWindows = candidate.replace("windows-2025", "windows-latest");
  assert.match(candidateWorkflowFailures(missingWindows).join("\n"), /win32-x64 on windows-2025/);
});

test("darwin-x64 is cross-built on the Apple silicon runner and still installed on Intel", () => {
  assert.ok(!jobSource(candidate, "native-binaries").includes("macos-15-intel"));
  assert.match(
    jobSource(candidate, "local-tarball-smoke"),
    /- os: macos-15-intel\n {12}slug: darwin-x64/,
  );
  assert.deepEqual(
    releaseNativeBuildPlatforms.map(({ slug }) => slug),
    ["linux-x64", "linux-arm64", "darwin-arm64", "win32-x64"],
  );
  assert.deepEqual(releaseCrossBuilds, [
    {
      runner: "macos-14",
      hostSlug: "darwin-arm64",
      slug: "darwin-x64",
      target: "x86_64-apple-darwin",
    },
  ]);
});

test("a cross-built slug must be produced by its own target and artifact", () => {
  for (const token of [
    "cross_target: x86_64-apple-darwin",
    "rustup target add ${{ matrix.cross_target }}",
    "KUZUSHI_NATIVE_TARGET: ${{ matrix.cross_target }}",
    "name: release-candidate-native-${{ matrix.cross_slug }}",
  ]) {
    assert.match(
      candidateWorkflowFailures(candidate.replace(token, "# removed")).join("\n"),
      /must cross-build darwin-x64 on macos-14/,
      token,
    );
  }
});

test("both darwin legs stay eligible for the self-hosted runner behind one opt-in", () => {
  assert.deepEqual(publishedSmokeWorkflowFailures(publishedSmoke), []);
  for (const job of ["native-binaries", "local-tarball-smoke"]) {
    assert.ok(jobSource(candidate, job).includes(selfHostedMatrixRunsOn), job);
  }
  assert.ok(jobSource(publishedSmoke, "published-install").includes(selfHostedMatrixRunsOn));
  // A tag push carries no inputs, so the publisher opts into the Mac by variable
  // and runs on hosted macOS otherwise.
  assert.match(publisher, /hosted: \$\{\{ vars\.KUZUSHI_RELEASE_SELF_HOSTED != 'true' \}\}/);

  const alwaysHosted = candidate.replace(selfHostedMatrixRunsOn, "runs-on: ${{ matrix.os }}");
  assert.match(
    candidateWorkflowFailures(alwaysHosted).join("\n"),
    /must select the self-hosted runner by matrix\.self_hosted/,
  );
});

test("only the translated darwin-x64 leg carries the Rosetta opt-in", () => {
  const smoke = jobSource(candidate, "local-tarball-smoke");
  assert.match(smoke, /- os: macos-15-intel\n {12}slug: darwin-x64\n.*rosetta: "1"/s);
  assert.ok(!/slug: darwin-arm64\n {12}self_hosted: true\n {12}rosetta:/.test(smoke));

  const armRosetta = candidate.replace(
    "          - os: macos-14\n            slug: darwin-arm64\n            self_hosted: true\n",
    '          - os: macos-14\n            slug: darwin-arm64\n            self_hosted: true\n            rosetta: "1"\n',
  );
  assert.match(
    candidateWorkflowFailures(armRosetta).join("\n"),
    /darwin-arm64 carries the wrong Rosetta opt-in/,
  );
});

test("no credentialed or write-permission job is eligible for the self-hosted runner", () => {
  assert.deepEqual(hostedOnlyCandidateJobs, ["identity", "assemble"]);
  assert.deepEqual(hostedOnlyPublisherJobs, ["publish-npm", "github-release", "promote-latest"]);
  for (const [source, jobs] of [
    [candidate, hostedOnlyCandidateJobs],
    [publisher, hostedOnlyPublisherJobs],
  ]) {
    for (const job of jobs) {
      const section = jobSource(source, job);
      assert.ok(section.includes("runs-on: ubuntu-24.04"), job);
      for (const label of selfHostedMacLabels) assert.ok(!section.includes(`"${label}"`), job);
    }
  }
  const leaked = publisher.replace(
    "  publish-npm:\n    needs: [preflight, candidate]\n    runs-on: ubuntu-24.04",
    '  publish-npm:\n    needs: [preflight, candidate]\n    runs-on: ["self-hosted","macOS","ARM64","kuzushi-mac"]',
  );
  assert.match(
    publisherWorkflowFailures(leaked).join("\n"),
    /publish-npm must pin a GitHub-hosted ubuntu runner/,
  );
});

function jobSource(source, jobName) {
  const start = source.indexOf(`\n  ${jobName}:\n`);
  const next = source.slice(start + 1).search(/\n {2}[a-z][a-z0-9-]*:\n/);
  return next === -1 ? source.slice(start) : source.slice(start, start + 1 + next);
}

test("release publisher remains candidate-tagged and main-bound", () => {
  const withoutMain = publisher.replace(
    "release tag must point at current origin/${DEFAULT_BRANCH}",
    "release tag accepted",
  );

  assert.match(publisherWorkflowFailures(withoutMain).join("\n"), /current origin/);
  assert.deepEqual(platformPublisherFailures(platformPublisher), []);
  assert.match(
    platformPublisherFailures(platformPublisher.replace('"candidate",', '"latest",')).join("\n"),
    /candidate/,
  );
});

test("all repository workflows use immutable external action refs", () => {
  const workflows = readdirSync(new URL("../.github/workflows/", import.meta.url))
    .filter((name) => /\.ya?ml$/.test(name))
    .map((name) => ({ name, source: workflow(name) }));
  assert.deepEqual(callGraphActionPinFailures(workflows), []);
  assert.deepEqual(actionlintImageFailures(fullCi), []);
  const reference = workflow("kuzushi-reference.yml");
  const unpinnedComment = reference.replace(
    "marocchino/sticky-pull-request-comment@5770ad5eb8f42dd2c4f34da00c94c5381e49af88",
    "marocchino/sticky-pull-request-comment@v3",
  );
  assert.match(
    callGraphActionPinFailures([{ name: "reference", source: unpinnedComment }]).join("\n"),
    /full commit pin/,
  );
  assert.deepEqual(
    callGraphActionPinFailures([
      { name: "quoted", source: 'jobs: {test: {steps: [{uses: "owner/action@v1"}]}}' },
    ]).length,
    1,
  );
  assert.deepEqual(
    callGraphActionPinFailures([
      { name: "comment", source: 'jobs: {test: {steps: [{run: "echo uses: owner/action@v1"}]}}' },
    ]),
    [],
  );

  const movable = candidate.replace(
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/checkout@v7",
  );
  assert.match(
    callGraphActionPinFailures([{ name: "candidate", source: movable }]).join("\n"),
    /full commit pin/,
  );
});

function workflow(name) {
  return readFileSync(new URL(`../.github/workflows/${name}`, import.meta.url), "utf8");
}

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  actionlintImageFailures,
  callGraphActionPinFailures,
  candidateWorkflowFailures,
  platformPublisherFailures,
  publisherWorkflowFailures,
  releaseCrossBuilds,
  releaseNativeBuildPlatforms,
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

function jobSource(source, jobName) {
  const start = source.indexOf(`\n  ${jobName}:\n`);
  const next = source.slice(start + 1).search(/\n {2}[a-z][a-z0-9-]*:\n/);
  return next === -1 ? source.slice(start) : source.slice(start, start + 1 + next);
}

test("release publisher remains latest-tagged and main-bound", () => {
  const withoutMain = publisher.replace(
    "release tag must point at current origin/${DEFAULT_BRANCH}",
    "release tag accepted",
  );

  assert.match(publisherWorkflowFailures(withoutMain).join("\n"), /current origin/);
  assert.deepEqual(platformPublisherFailures(platformPublisher), []);
  assert.match(
    platformPublisherFailures(platformPublisher.replace('"latest",', '"alpha",')).join("\n"),
    /latest/,
  );
});

test("the complete release call graph uses immutable action refs", () => {
  const workflows = [
    { name: "candidate", source: candidate },
    { name: "publisher", source: publisher },
    { name: "full CI", source: fullCi },
    { name: "published smoke", source: publishedSmoke },
  ];
  assert.deepEqual(callGraphActionPinFailures(workflows), []);
  assert.deepEqual(actionlintImageFailures(fullCi), []);

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

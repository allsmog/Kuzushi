import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  artifactSizeFailures,
  createArtifactRecord,
  expectedArtifactSpecifications,
  PLATFORM_UNPACKED_BUDGET,
  releaseManifestFailures,
  verifyReleaseManifest,
  writeReleaseManifest,
} from "./release-artifact-contract.mjs";

const sha = "1".repeat(40);
const version = "1.2.3-alpha.4";

test("one manifest authenticates every release file", () => {
  const directory = fixtureBundle();
  assert.equal(verifyReleaseManifest(directory, sha, version).files.length, 12);
});

test("manifest verification rejects changed bytes and extra files", () => {
  const directory = fixtureBundle();
  writeFileSync(path.join(directory, "packages", `kuzushi-${version}.tgz`), "changed");
  writeFileSync(path.join(directory, "extra.txt"), "extra");
  assert.throws(() => verifyReleaseManifest(directory, sha, version), /SHA256|size/);
  assert.throws(() => verifyReleaseManifest(directory, sha, version), /bundle adds extra\.txt/);
});

test("manifest paths and established package budgets fail closed", () => {
  const directory = fixtureBundle();
  const manifest = verifyReleaseManifest(directory, sha, version);
  manifest.files[0].file = "../outside.tgz";
  const failures = releaseManifestFailures(directory, manifest, sha, version);
  assert.ok(failures.some((failure) => failure.includes("unsafe path")));
  assert.notDeepEqual(
    artifactSizeFailures({ kind: "root-npm", file: "root.tgz", size: 10 * 1024 * 1024 + 1 }),
    [],
  );
  assert.deepEqual(
    artifactSizeFailures({
      kind: "platform-npm",
      file: "platform.tgz",
      size: 0,
      unpackedSize: PLATFORM_UNPACKED_BUDGET,
    }),
    [],
  );
  assert.notDeepEqual(
    artifactSizeFailures({
      kind: "platform-npm",
      file: "platform.tgz",
      size: 0,
      unpackedSize: PLATFORM_UNPACKED_BUDGET + 1,
    }),
    [],
  );
});

test("malformed manifest records report failures instead of crashing", () => {
  const directory = fixtureBundle();
  const manifest = verifyReleaseManifest(directory, sha, version);
  manifest.files[0] = { file: "release-manifest.json" };
  assert.doesNotThrow(() => releaseManifestFailures(directory, manifest, sha, version));
  assert.ok(
    releaseManifestFailures(directory, manifest, sha, version).some((failure) =>
      failure.includes("fields must be exactly"),
    ),
  );
});

function fixtureBundle() {
  const directory = mkdtempSync(path.join(tmpdir(), "kuzushi-release-artifacts-"));
  const specifications = expectedArtifactSpecifications(version);
  const records = specifications.map((specification) => {
    const absolute = path.join(directory, specification.file);
    mkdirSync(path.dirname(absolute), { recursive: true });
    writeFileSync(absolute, `${specification.kind}:${specification.slug ?? "root"}\n`);
    const npmMetadata = specification.kind.endsWith("-npm") ? { unpackedSize: 100 } : undefined;
    return createArtifactRecord({ directory, specification, npmMetadata });
  });
  writeReleaseManifest(directory, sha, version, records);
  return directory;
}

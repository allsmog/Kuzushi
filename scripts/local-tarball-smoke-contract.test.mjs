import assert from "node:assert/strict";
import test from "node:test";
import {
  localConsumerManifest,
  machineArchitecture,
  nodeArchitectureFailure,
  processIsTranslated,
  rosettaOverrideEnvVar,
  rosettaOverrideRequested,
  rosettaTranslationInstalled,
  selectLocalTarballs,
  smokeExecutionPlan,
  translatedCommand,
} from "./local-tarball-smoke-contract.mjs";

const manifest = {
  files: [
    { kind: "root-npm", name: "kuzushi", file: "packages/kuzushi-1.0.0.tgz" },
    {
      kind: "platform-npm",
      name: "@kuzushi/linux-x64",
      slug: "linux-x64",
      file: "packages/kuzushi-linux-x64-1.0.0.tgz",
    },
  ],
};

test("local consumer installs both exact candidate tarballs", () => {
  const selected = selectLocalTarballs(manifest, "/candidate", "linux-x64", "linux", "x64");
  const consumer = localConsumerManifest("1.0.0", selected);
  assert.equal(consumer.dependencies.kuzushi, "file:///candidate/packages/kuzushi-1.0.0.tgz");
  assert.equal(
    consumer.dependencies["@kuzushi/linux-x64"],
    "file:///candidate/packages/kuzushi-linux-x64-1.0.0.tgz",
  );
});

test("a smoke leg cannot claim a foreign runner platform", () => {
  assert.throws(
    () => selectLocalTarballs(manifest, "/candidate", "linux-x64", "darwin", "arm64"),
    /cannot run on/,
  );
});

test("a host smoke reports no translation", () => {
  assert.deepEqual(smokeExecutionPlan({ slug: "linux-x64", platform: "linux", arch: "x64" }), {
    hostSlug: "linux-x64",
    smokedSlug: "linux-x64",
    translation: "none",
  });
});

test("an unknown slug is refused before any host comparison", () => {
  assert.throws(
    () => smokeExecutionPlan({ slug: "darwin-riscv64", platform: "darwin", arch: "arm64" }),
    /unknown release platform/,
  );
});

test("darwin-x64 on darwin-arm64 still refuses without the explicit opt-in", () => {
  assert.throws(
    () => smokeExecutionPlan({ slug: "darwin-x64", platform: "darwin", arch: "arm64" }),
    new RegExp(`requires an explicit ${rosettaOverrideEnvVar}=1 opt-in`),
  );
});

test("the opt-in still refuses a host without Rosetta installed", () => {
  assert.throws(
    () =>
      smokeExecutionPlan({
        slug: "darwin-x64",
        platform: "darwin",
        arch: "arm64",
        allowRosetta: true,
        rosettaInstalled: false,
      }),
    /Rosetta 2 is not installed/,
  );
});

test("an opt-in on a Rosetta host records the host, the smoked slug, and the translation", () => {
  const plan = smokeExecutionPlan({
    slug: "darwin-x64",
    platform: "darwin",
    arch: "arm64",
    allowRosetta: true,
    rosettaInstalled: true,
  });
  assert.deepEqual(plan, {
    hostSlug: "darwin-arm64",
    smokedSlug: "darwin-x64",
    translation: "rosetta",
  });
  assert.deepEqual(translatedCommand(plan, "/native/kuzushi", ["--version"]), {
    command: "/usr/bin/arch",
    args: ["-x86_64", "/native/kuzushi", "--version"],
  });
});

test("the opt-in never unlocks a pairing Rosetta cannot translate", () => {
  for (const [slug, platform, arch] of [
    ["darwin-arm64", "darwin", "x64"],
    ["linux-x64", "darwin", "arm64"],
    ["win32-x64", "darwin", "arm64"],
  ]) {
    assert.throws(
      () =>
        smokeExecutionPlan({
          slug,
          platform,
          arch,
          allowRosetta: true,
          rosettaInstalled: true,
        }),
      /cannot run on/,
    );
  }
});

test("an untranslated plan launches the command unchanged", () => {
  const plan = smokeExecutionPlan({ slug: "linux-x64", platform: "linux", arch: "x64" });
  assert.deepEqual(translatedCommand(plan, "node", ["a"]), { command: "node", args: ["a"] });
});

test("the override is opt-in by exact value and the probe is the only host question", () => {
  assert.equal(rosettaOverrideRequested({}), false);
  assert.equal(rosettaOverrideRequested({ [rosettaOverrideEnvVar]: "0" }), false);
  assert.equal(rosettaOverrideRequested({ [rosettaOverrideEnvVar]: "1" }), true);
  assert.equal(rosettaTranslationInstalled({ markerExists: () => true }), true);
  assert.equal(rosettaTranslationInstalled({ markerExists: () => false, probe: () => true }), true);
  assert.equal(
    rosettaTranslationInstalled({ markerExists: () => false, probe: () => false }),
    false,
  );
});

test("a translated process reports the machine it runs on, not the arch it reports", () => {
  assert.equal(machineArchitecture("x64", true), "arm64");
  assert.equal(machineArchitecture("x64", false), "x64");
  assert.equal(machineArchitecture("arm64", false), "arm64");
  assert.equal(processIsTranslated({ platform: "linux", probe: () => true }), false);
  assert.equal(processIsTranslated({ platform: "darwin", probe: () => true }), true);
  assert.equal(processIsTranslated({ platform: "darwin", probe: () => false }), false);
});

test("a translated leg refuses to smoke darwin-x64 through an arm64 Node", () => {
  const translated = smokeExecutionPlan({
    slug: "darwin-x64",
    platform: "darwin",
    arch: "arm64",
    allowRosetta: true,
    rosettaInstalled: true,
  });
  assert.match(nodeArchitectureFailure(translated, "arm64"), /must run under an x64 Node/);
  assert.equal(nodeArchitectureFailure(translated, "x64"), null);

  const native = smokeExecutionPlan({ slug: "darwin-arm64", platform: "darwin", arch: "arm64" });
  assert.equal(nodeArchitectureFailure(native, "arm64"), null);
});

test("a selected tarball carries the execution plan into the receipt", () => {
  const selected = selectLocalTarballs(manifest, "/candidate", "linux-x64", "linux", "x64");
  assert.equal(selected.plan.translation, "none");
  assert.equal(selected.plan.hostSlug, "linux-x64");
});

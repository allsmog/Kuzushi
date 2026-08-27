import assert from "node:assert/strict";
import test from "node:test";
import { localConsumerManifest, selectLocalTarballs } from "./local-tarball-smoke-contract.mjs";

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

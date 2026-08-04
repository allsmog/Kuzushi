import assert from "node:assert/strict";
import test from "node:test";
import { validatePublicCoreLock } from "./public-core-cargo-lock.mjs";

function lock(packages) {
  return `# generated\nversion = 4\n\n${packages
    .map(
      ({ name, version = "0.1.0", source, checksum }) => `[[package]]
name = "${name}"
version = "${version}"${source ? `\nsource = "${source}"` : ""}${
        checksum ? `\nchecksum = "${checksum}"` : ""
      }\n`,
    )
    .join("\n")}`;
}

const privateSource = "git+https://github.com/allsmog/oxidized-joern.git?rev=deadbeef#deadbeef";
const registrySource = "registry+https://github.com/rust-lang/crates.io-index";

function fullLock() {
  return lock([
    { name: "kuzushi-core", version: "1.0.0" },
    { name: "kuzushi-cpg", version: "1.0.0" },
    { name: "cpg-analysis", version: "0.2.0", source: privateSource },
    { name: "cpg-cli", source: privateSource },
    { name: "cpg-core", source: privateSource },
    { name: "cpg-incremental", source: privateSource },
    { name: "cpg-language", source: privateSource },
    { name: "serde", version: "1.0.0", source: registrySource, checksum: "abc" },
  ]);
}

function publicLock(extra = []) {
  return lock([
    { name: "kuzushi-core", version: "1.0.0" },
    { name: "kuzushi-cpg", version: "1.0.0" },
    { name: "cpg-analysis", version: "0.2.0" },
    { name: "cpg-cli" },
    { name: "cpg-core" },
    { name: "cpg-incremental" },
    { name: "serde", version: "1.0.0", source: registrySource, checksum: "abc" },
    ...extra,
  ]);
}

test("accepts local resolver stubs without changing retained packages", () => {
  const result = validatePublicCoreLock(fullLock(), publicLock());

  assert.equal(result.removedPrivatePackages, 5);
  assert.equal(result.resolverStubs, 4);
});

test("rejects a private source that survives public resolution", () => {
  assert.throws(
    () =>
      validatePublicCoreLock(
        fullLock(),
        publicLock([{ name: "cpg-frontend", source: privateSource }]),
      ),
    /still resolves private packages/,
  );
});

test("rejects registry drift or a new external dependency", () => {
  assert.throws(
    () =>
      validatePublicCoreLock(
        fullLock(),
        publicLock([
          {
            name: "serde_json",
            version: "1.0.0",
            source: registrySource,
            checksum: "def",
          },
        ]),
      ),
    /introduced or changed external package serde_json/,
  );
});

test("rejects a missing resolver stub", () => {
  const missing = publicLock().replace('[[package]]\nname = "cpg-cli"\nversion = "0.1.0"\n\n', "");

  assert.throws(
    () => validatePublicCoreLock(fullLock(), missing),
    /one local resolver stub for cpg-cli/,
  );
});

test("rejects a resolver stub with the wrong private package version", () => {
  const wrongVersion = publicLock().replace(
    'name = "cpg-analysis"\nversion = "0.2.0"',
    'name = "cpg-analysis"\nversion = "0.1.0"',
  );

  assert.throws(
    () => validatePublicCoreLock(fullLock(), wrongVersion),
    /one local resolver stub for cpg-analysis/,
  );
});

test("rejects removal of an ordinary workspace package", () => {
  const missing = publicLock().replace(
    '[[package]]\nname = "kuzushi-cpg"\nversion = "1.0.0"\n\n',
    "",
  );

  assert.throws(
    () => validatePublicCoreLock(fullLock(), missing),
    /dropped workspace\/path package kuzushi-cpg/,
  );
});

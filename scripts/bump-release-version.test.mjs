import assert from "node:assert/strict";
import test from "node:test";
import { bumpReleaseSources } from "./bump-release-version.mjs";

function sources() {
  return {
    packageJson: '{"name":"kuzushi","version":"1.2.3-alpha.1"}\n',
    cargoToml:
      '[workspace]\nmembers = [\n  "crates/kuzushi",\n  "crates/kuzushi-core",\n]\n' +
      '[workspace.package]\nversion = "1.2.3-alpha.1"\n',
    cargoLock:
      '[[package]]\nname = "kuzushi"\nversion = "1.2.3-alpha.1"\n\n' +
      '[[package]]\nname = "kuzushi-core"\nversion = "1.2.3-alpha.1"\n',
    dynamicHost: 'const HOST_PACKAGE_VERSION = "1.2.3-alpha.1";\n',
  };
}

test("release bump updates every version-bearing contract", () => {
  const bumped = bumpReleaseSources(sources(), "1.2.3-alpha.2");

  assert.equal(JSON.parse(bumped.packageJson).version, "1.2.3-alpha.2");
  assert.match(bumped.cargoToml, /version = "1\.2\.3-alpha\.2"/);
  assert.equal(bumped.cargoLock.match(/version = "1\.2\.3-alpha\.2"/g)?.length, 2);
  assert.match(bumped.dynamicHost, /HOST_PACKAGE_VERSION = "1\.2\.3-alpha\.2"/);
});

test("release bump refuses drift and invalid versions before writing", () => {
  const drifted = sources();
  drifted.dynamicHost = 'const HOST_PACKAGE_VERSION = "9.9.9";\n';

  assert.throws(() => bumpReleaseSources(drifted, "1.2.3-alpha.2"), /already inconsistent/);
  assert.throws(() => bumpReleaseSources(sources(), "1.2.3+local"), /without build metadata/);
});

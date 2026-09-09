import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { nativePlatformPackage, nativeRuntimeBinaries } from "./native-runtime-contract.mjs";

const repo = fileURLToPath(new URL("..", import.meta.url));
const posix = { skip: process.platform === "win32" };

test(
  "source wrapper builds before choosing Cargo output over stale bundled and target binaries",
  posix,
  (t) => {
    const fixture = checkout(t);
    fakeRuntime(
      path.join(fixture.root, "native", `${process.platform}-${process.arch}`),
      "stale-bundle",
    );
    fakeRuntime(path.join(fixture.root, "target", "debug"), "stale-debug");
    const result = launch(fixture, ["a path with spaces", "--target", "../selected"]);
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.marker, "current-source");
    assert.equal(output.cwd, fixture.cwd);
    assert.deepEqual(output.argv, ["a path with spaces", "--target", "../selected"]);
    assert.equal(output.name, "kuzushi");
    assert.equal(output.sidecar, "current-source");
    const build = JSON.parse(readFileSync(path.join(fixture.root, "build-call.json")));
    assert.equal(build.cwd, fixture.root);
    assert.equal(build.targetDir, "custom output");
    assert.ok(build.args.includes("--locked"));
    for (const name of nativeRuntimeBinaries)
      assert.ok(build.args.includes(name === "kuzushi" ? "kuzushi-cli" : name));
  },
);

test(
  "failed source build preserves failure status and cannot fall through to a stale binary",
  posix,
  (t) => {
    const fixture = checkout(t);
    fakeRuntime(path.join(fixture.root, "native", `${process.platform}-${process.arch}`), "stale");
    const result = launch(fixture, [], { TEST_BUILD_STATUS: "41" });
    assert.equal(result.status, 41);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /compiler diagnostic/);
    assert.match(result.stderr, /Source build failed/);
  },
);

test("incomplete Cargo output fails even when an older complete runtime exists", posix, (t) => {
  const fixture = checkout(t);
  fakeRuntime(path.join(fixture.root, "target", "release"), "stale");
  const artifacts = JSON.parse(readFileSync(path.join(fixture.root, "artifacts.json")));
  writeFileSync(path.join(fixture.root, "artifacts.json"), JSON.stringify(artifacts.slice(0, -1)));
  const result = launch(fixture);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /did not report an executable for kuzushi-mcp-x-ray/);
});

test("source command fails clearly when Cargo is unavailable", posix, (t) => {
  const fixture = checkout(t);
  const result = launch(fixture, [], { PATH: path.join(fixture.root, "empty-path") });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Could not start Cargo/);
});

test(
  "interrupted builds preserve their signal status even with an incomplete JSON line",
  posix,
  (t) => {
    const fixture = checkout(t);
    const result = launch(fixture, [], { TEST_BUILD_SIGNAL: "SIGTERM" });
    assert.equal(result.status, 143);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /Source build failed/);
  },
);

test(
  "packaged wrapper runs the installed native package with no Cargo or inherited PATH",
  posix,
  (t) => {
    const fixture = checkout(t, false);
    const selected = nativePlatformPackage();
    const packageRoot = path.join(fixture.root, "node_modules", selected.packageName);
    mkdirSync(packageRoot, { recursive: true });
    writeFileSync(
      path.join(packageRoot, "package.json"),
      JSON.stringify({ name: selected.packageName }),
    );
    fakeRuntime(path.join(packageRoot, "bin"), "installed-package");
    const result = launch(fixture, [], { PATH: "" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).marker, "installed-package");
    assert.equal(JSON.parse(result.stdout).sidecar, "installed-package");
  },
);

test(
  "an explicit native override bypasses a source build and follows its real companion directory",
  posix,
  (t) => {
    const fixture = checkout(t);
    const runtime = fakeRuntime(path.join(fixture.root, "specific runtime"), "override");
    const alias = path.join(fixture.cwd, "kuzushi");
    symlinkSync(path.join(runtime, "kuzushi"), alias);
    const result = launch(fixture, [], { KUZUSHI_NATIVE_BIN: alias, PATH: "" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).sidecar, "override");
    assert.equal(JSON.parse(result.stdout).marker, "override");
  },
);

test(
  "invalid explicit native overrides are refused without source or package fallback",
  posix,
  (t) => {
    const fixture = checkout(t);
    const wrong = path.join(fixture.cwd, "wrong-name");
    writeFileSync(wrong, "file");
    for (const invalid of [wrong, fixture.cwd, path.join(fixture.cwd, "missing", "kuzushi")]) {
      const result = launch(fixture, [], { KUZUSHI_NATIVE_BIN: invalid });
      assert.equal(result.status, 127, result.stderr);
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /KUZUSHI_NATIVE_BIN/);
    }
  },
);

test("kz identity and native failure/signal statuses survive the wrapper", posix, (t) => {
  const fixture = checkout(t);
  const alias = path.join(fixture.root, "bin", "kz");
  symlinkSync("kuzushi-rs.mjs", alias);
  const result = launch(fixture, [], {}, alias);
  assert.equal(JSON.parse(result.stdout).name, "kz");
  assert.equal(launch(fixture, ["--exit7"]).status, 7);
  const killed = launch(fixture, ["--terminate"]);
  assert.equal(killed.status, 143);
  assert.match(killed.stderr, /SIGTERM/);
});

test(
  "dev runner uses Cargo paths while preserving the caller's target and command arguments",
  posix,
  (t) => {
    const fixture = checkout(t);
    const result = launch(
      fixture,
      ["--", "--target", "target with spaces"],
      {},
      path.join(fixture.root, "scripts", "run-native-dev.mjs"),
    );
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.cwd, fixture.cwd);
    assert.equal(output.sidecar, "current-source");
    assert.deepEqual(output.argv, ["--target", "target with spaces"]);
  },
);

function checkout(t, source = true) {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "kuzushi launcher-")));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const file of [
    "bin/kuzushi-rs.mjs",
    "scripts/native-runtime-contract.mjs",
    "scripts/source-native-runtime.mjs",
    "scripts/run-native-dev.mjs",
  ]) {
    mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    copyFileSync(path.join(repo, file), path.join(root, file));
  }
  const cwd = path.join(root, "operator target");
  mkdirSync(cwd);
  const fakeBin = path.join(root, "tools");
  mkdirSync(fakeBin);
  if (source) {
    mkdirSync(path.join(root, "crates", "kuzushi-cli"), { recursive: true });
    writeFileSync(path.join(root, "crates", "kuzushi-cli", "Cargo.toml"), "fixture");
    writeFileSync(path.join(root, "Cargo.toml"), "fixture");
  }
  const output = fakeRuntime(
    path.join(root, "custom output", "configured-target", "debug"),
    "current-source",
  );
  const artifacts = nativeRuntimeBinaries.map((name) => ({
    reason: "compiler-artifact",
    target: { name, kind: ["bin"] },
    executable: path.join(output, name),
  }));
  writeFileSync(path.join(root, "artifacts.json"), JSON.stringify(artifacts));
  executable(
    path.join(fakeBin, "cargo"),
    `
    const fs = require("node:fs");
    fs.writeFileSync("build-call.json", JSON.stringify({cwd:process.cwd(),args:process.argv.slice(2),targetDir:process.env.CARGO_TARGET_DIR}));
    if(process.env.TEST_BUILD_SIGNAL) {
      process.stdout.write("{");
      process.kill(process.pid,process.env.TEST_BUILD_SIGNAL);
    }
    if(process.env.TEST_BUILD_STATUS) {
      console.log(JSON.stringify({reason:"compiler-message",message:{rendered:"compiler diagnostic\\n"}}));
      process.exit(Number(process.env.TEST_BUILD_STATUS));
    }
    for(const message of JSON.parse(fs.readFileSync("artifacts.json"))) console.log(JSON.stringify(message));
  `,
  );
  return { root, cwd, fakeBin };
}

function fakeRuntime(dir, marker) {
  mkdirSync(dir, { recursive: true });
  for (const name of nativeRuntimeBinaries) {
    const body =
      name === "kuzushi"
        ? `
      if(process.argv.includes("--exit7")) process.exit(7);
      if(process.argv.includes("--terminate")) process.kill(process.pid,"SIGTERM");
      const child=require("node:child_process").spawnSync("kuzushi-mcp-cpg",[],{encoding:"utf8"});
      console.log(JSON.stringify({marker:${JSON.stringify(marker)},cwd:process.cwd(),argv:process.argv.slice(2),name:process.env.KUZUSHI_CLI_NAME,sidecar:child.stdout?.trim()}));
    `
        : `console.log(${JSON.stringify(marker)});`;
    executable(path.join(dir, name), body);
  }
  return dir;
}

function executable(file, body) {
  writeFileSync(file, `#!${process.execPath}\n${body}\n`, { mode: 0o755 });
}

function launch(
  fixture,
  args = [],
  env = {},
  script = path.join(fixture.root, "bin", "kuzushi-rs.mjs"),
) {
  return spawnSync(process.execPath, [script, ...args], {
    cwd: fixture.cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      KUZUSHI_NATIVE_BIN: "",
      KUZUSHI_CLI_NAME: "untrusted-alias",
      TEST_BUILD_STATUS: "",
      CARGO_TARGET_DIR: "custom output",
      PATH: fixture.fakeBin,
      ...env,
    },
  });
}

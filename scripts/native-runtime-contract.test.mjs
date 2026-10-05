import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";

import {
  cargoNativeBuildArgs,
  cargoReleaseBuildArgs,
  cargoReleaseDir,
  nativePlatformForSlug,
  nativePlatformPackages,
  nativeSlugForTarget,
  nativeTargetTriples,
  resolveNativeTarget,
  targetTripleForSlug,
} from "./native-runtime-contract.mjs";

test("every required release platform has exactly one Rust target triple", () => {
  const slugs = nativePlatformPackages.map(({ slug }) => slug);
  assert.deepEqual(
    nativeTargetTriples.map(({ slug }) => slug),
    slugs,
  );
  for (const slug of slugs) {
    assert.equal(nativeSlugForTarget(targetTripleForSlug(slug)), slug);
  }
  assert.deepEqual(
    nativeTargetTriples.map(({ triple }) => triple),
    [
      "x86_64-unknown-linux-gnu",
      "aarch64-unknown-linux-gnu",
      "x86_64-apple-darwin",
      "aarch64-apple-darwin",
      "x86_64-pc-windows-msvc",
    ],
  );
});

test("an unmapped triple or slug is refused rather than guessed", () => {
  assert.throws(
    () => nativeSlugForTarget("riscv64gc-unknown-linux-gnu"),
    /unsupported Rust target/,
  );
  assert.throws(() => targetTripleForSlug("darwin-riscv64"), /unsupported release platform/);
});

test("a host build keeps the exact prior cargo argument list", () => {
  const args = cargoReleaseBuildArgs();
  assert.deepEqual(args.slice(0, 3), ["build", "--locked", "--release"]);
  assert.ok(!args.includes("--target"));
  assert.deepEqual(cargoNativeBuildArgs({ release: true }), args);
});

test("a cross build appends the requested target triple", () => {
  const args = cargoReleaseBuildArgs({ target: "x86_64-apple-darwin" });
  assert.deepEqual(args.slice(0, 5), [
    "build",
    "--locked",
    "--release",
    "--target",
    "x86_64-apple-darwin",
  ]);
  assert.throws(() => cargoNativeBuildArgs({ target: "wasm32-wasi" }), /unsupported Rust target/);
});

test("the target selection is explicit and never inferred from the host", () => {
  assert.equal(resolveNativeTarget([], {}), undefined);
  assert.equal(resolveNativeTarget([], { KUZUSHI_NATIVE_TARGET: "  " }), undefined);
  assert.equal(
    resolveNativeTarget([], { KUZUSHI_NATIVE_TARGET: "x86_64-apple-darwin" }),
    "x86_64-apple-darwin",
  );
  assert.equal(
    resolveNativeTarget(["--target", "aarch64-apple-darwin"], {
      KUZUSHI_NATIVE_TARGET: "x86_64-apple-darwin",
    }),
    "aarch64-apple-darwin",
  );
  assert.equal(resolveNativeTarget(["--target=win32"], {}), "win32");
  assert.throws(() => resolveNativeTarget(["--target"], {}), /requires a Rust target triple/);
});

test("cargo output is read from the target-specific release directory", () => {
  const repo = path.resolve("repo");
  const shared = path.resolve("shared");
  assert.equal(cargoReleaseDir(repo, {}, undefined), path.join(repo, "target", "release"));
  assert.equal(
    cargoReleaseDir(repo, {}, "x86_64-apple-darwin"),
    path.join(repo, "target", "x86_64-apple-darwin", "release"),
  );
  assert.equal(
    cargoReleaseDir(repo, { CARGO_TARGET_DIR: shared }, undefined),
    path.join(shared, "release"),
  );
  assert.equal(
    cargoReleaseDir(repo, { CARGO_TARGET_DIR: "out" }, undefined),
    path.join(repo, "out", "release"),
  );
});

test("the staged platform comes from the slug, not the building host", () => {
  assert.equal(nativePlatformForSlug("darwin-x64"), "darwin");
  assert.equal(nativePlatformForSlug("win32-x64"), "win32");
  assert.equal(nativePlatformForSlug("linux-arm64"), "linux");
});

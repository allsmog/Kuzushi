#!/usr/bin/env node

import { join, resolve } from "node:path";

/**
 * The native runtime payload shipped for each supported platform.
 *
 * Keep package names and binary names together here so local staging, CI,
 * npm packaging, and release archives cannot silently publish different
 * products.
 */
export const nativeRuntimePackages = Object.freeze([
  { packageName: "kuzushi-cli", binaryName: "kuzushi" },
  { packageName: "kuzushi-mcp-gtags", binaryName: "kuzushi-mcp-gtags" },
  { packageName: "kuzushi-mcp-clang", binaryName: "kuzushi-mcp-clang" },
  { packageName: "kuzushi-mcp-cpg", binaryName: "kuzushi-mcp-cpg" },
  { packageName: "kuzushi-mcp-treesitter", binaryName: "kuzushi-mcp-treesitter" },
  { packageName: "kuzushi-mcp-codeql", binaryName: "kuzushi-mcp-codeql" },
  { packageName: "kuzushi-mcp-revng", binaryName: "kuzushi-mcp-revng" },
  { packageName: "kuzushi-mcp-context", binaryName: "kuzushi-mcp-context" },
  {
    packageName: "kuzushi-mcp-entry-points",
    binaryName: "kuzushi-mcp-entry-points",
  },
  { packageName: "kuzushi-mcp-findings", binaryName: "kuzushi-mcp-findings" },
  {
    packageName: "kuzushi-mcp-threat-model",
    binaryName: "kuzushi-mcp-threat-model",
  },
  {
    packageName: "kuzushi-mcp-threat-intel",
    binaryName: "kuzushi-mcp-threat-intel",
  },
  { packageName: "kuzushi-mcp-x-ray", binaryName: "kuzushi-mcp-x-ray" },
]);

export const nativeRuntimeBinaries = Object.freeze(
  nativeRuntimePackages.map(({ binaryName }) => binaryName),
);

export const nativePlatformPackages = Object.freeze([
  {
    slug: "linux-x64",
    packageName: "@kuzushi/linux-x64",
    os: "linux",
    cpu: "x64",
    libc: "glibc",
    required: true,
  },
  {
    slug: "linux-arm64",
    packageName: "@kuzushi/linux-arm64",
    os: "linux",
    cpu: "arm64",
    libc: "glibc",
    required: true,
  },
  {
    slug: "darwin-x64",
    packageName: "@kuzushi/darwin-x64",
    os: "darwin",
    cpu: "x64",
    required: true,
  },
  {
    slug: "darwin-arm64",
    packageName: "@kuzushi/darwin-arm64",
    os: "darwin",
    cpu: "arm64",
    required: true,
  },
  {
    slug: "win32-x64",
    packageName: "@kuzushi/win32-x64",
    os: "win32",
    cpu: "x64",
    required: true,
  },
]);

export function nativePlatformPackage(platform = process.platform, arch = process.arch) {
  return nativePlatformPackages.find(({ os, cpu }) => os === platform && cpu === arch);
}

export function nativeExecutableName(binaryName, platform = process.platform) {
  return platform === "win32" ? `${binaryName}.exe` : binaryName;
}

export function nativePlatformSlug(platform = process.platform, arch = process.arch) {
  return `${platform}-${arch}`;
}

/**
 * The Rust target triple that produces each shipped platform slug.
 *
 * Cross-compiling a slug is only honest while the triple and the slug stay
 * paired here: staging reads `target/<triple>/release` and publishes it as
 * `native/<slug>`, so an unmapped triple must fail rather than guess.
 */
export const nativeTargetTriples = Object.freeze([
  { slug: "linux-x64", triple: "x86_64-unknown-linux-gnu" },
  { slug: "linux-arm64", triple: "aarch64-unknown-linux-gnu" },
  { slug: "darwin-x64", triple: "x86_64-apple-darwin" },
  { slug: "darwin-arm64", triple: "aarch64-apple-darwin" },
  { slug: "win32-x64", triple: "x86_64-pc-windows-msvc" },
]);

export function nativeSlugForTarget(triple) {
  const mapping = nativeTargetTriples.find((candidate) => candidate.triple === triple);
  if (!mapping) {
    throw new Error(
      `unsupported Rust target ${triple}; expected one of ${nativeTargetTriples
        .map(({ triple: known }) => known)
        .join(", ")}`,
    );
  }
  return mapping.slug;
}

export function targetTripleForSlug(slug) {
  const mapping = nativeTargetTriples.find((candidate) => candidate.slug === slug);
  if (!mapping) {
    throw new Error(
      `unsupported release platform ${slug}; expected one of ${nativeTargetTriples
        .map(({ slug: known }) => known)
        .join(", ")}`,
    );
  }
  return mapping.triple;
}

export function nativePlatformForSlug(slug) {
  const platform = slug.slice(0, slug.lastIndexOf("-"));
  if (!platform) throw new Error(`release platform slug ${slug} has no platform segment`);
  return platform;
}

/**
 * The cross-target selection: an explicit `--target <triple>` argument wins over
 * the documented `KUZUSHI_NATIVE_TARGET` environment value, and neither is ever
 * inferred from the host. An absent selection means an ordinary host build.
 */
export function resolveNativeTarget(argv, env) {
  const flag = argv.indexOf("--target");
  if (flag !== -1) {
    const value = argv[flag + 1];
    if (!value) throw new Error("--target requires a Rust target triple");
    return value;
  }
  const inline = argv.find((argument) => argument.startsWith("--target="));
  if (inline) return inline.slice("--target=".length) || undefined;
  const configured = env.KUZUSHI_NATIVE_TARGET?.trim();
  return configured ? configured : undefined;
}

/** Cargo writes cross-target output under `<target-dir>/<triple>/release`. */
export function cargoReleaseDir(root, env, target) {
  const configured = env.CARGO_TARGET_DIR?.trim();
  const base = configured ? resolve(root, configured) : join(root, "target");
  return target ? join(base, target, "release") : join(base, "release");
}

export function cargoReleaseBuildArgs({ target } = {}) {
  return cargoNativeBuildArgs({ release: true, target });
}

export function cargoNativeBuildArgs({ release = false, target } = {}) {
  if (target !== undefined) nativeSlugForTarget(target);
  return [
    "build",
    "--locked",
    ...(release ? ["--release"] : []),
    ...(target ? ["--target", target] : []),
    ...nativeRuntimePackages.flatMap(({ packageName }) => ["--package", packageName]),
  ];
}

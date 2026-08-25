#!/usr/bin/env node

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

export function cargoReleaseBuildArgs() {
  return cargoNativeBuildArgs({ release: true });
}

export function cargoNativeBuildArgs({ release = false } = {}) {
  return [
    "build",
    "--locked",
    ...(release ? ["--release"] : []),
    ...nativeRuntimePackages.flatMap(({ packageName }) => ["--package", packageName]),
  ];
}

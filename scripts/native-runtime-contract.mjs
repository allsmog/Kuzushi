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
  { packageName: "kuzushi-mcp-joern", binaryName: "kuzushi-mcp-joern" },
  { packageName: "kuzushi-mcp-treesitter", binaryName: "kuzushi-mcp-treesitter" },
  { packageName: "kuzushi-mcp-codeql", binaryName: "kuzushi-mcp-codeql" },
  { packageName: "kuzushi-mcp-revng", binaryName: "kuzushi-mcp-revng" },
  { packageName: "kuzushi-mcp-context", binaryName: "kuzushi-mcp-context" },
  {
    packageName: "kuzushi-mcp-entry-points",
    binaryName: "kuzushi-mcp-entry-points",
  },
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

export function nativeExecutableName(binaryName, platform = process.platform) {
  return platform === "win32" ? `${binaryName}.exe` : binaryName;
}

export function nativePlatformSlug(platform = process.platform, arch = process.arch) {
  return `${platform}-${arch}`;
}

export function cargoReleaseBuildArgs() {
  return [
    "build",
    "--locked",
    "--release",
    ...nativeRuntimePackages.flatMap(({ packageName }) => ["--package", packageName]),
  ];
}

#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const shared = [
  /^\.github\//,
  /^Cargo\.(toml|lock)$/,
  /^rust-toolchain/,
  /^scripts\/select-platform-runtime/,
];
const suites = {
  mcp: [/^crates\/kuzushi-(mcp-common|codeindex)\//],
  sandbox: [/^crates\/kuzushi-sandbox\//],
  // Core infrastructure may move between modules. Only explicit domain
  // folders are excluded; unknown core paths keep the platform contract on.
  core: [/^crates\/kuzushi-core\/(?!src\/(?:.*\/)?domain\/)/],
  terminal: [/^crates\/kuzushi-tui\//],
  launcher: [
    /^bin\//,
    /^package\.json$/,
    /^pnpm-(lock|workspace)\.yaml$/,
    /^npm\/platform-packages\//,
    /^scripts\/(native-|stage-native|build-native|run-native|postinstall|smoke-.*runtime|resolve-native|publish-platform)/,
  ],
};

export function selectPlatformRuntime(paths) {
  const all = paths === null || paths.some(requiresAllSuites);
  return Object.fromEntries(
    Object.entries(suites).map(([suite, patterns]) => [
      suite,
      all || paths.some((file) => matchesAny(file, patterns)),
    ]),
  );
}

function requiresAllSuites(file) {
  if (matchesAny(file, shared)) return true;
  if (Object.values(suites).some((patterns) => matchesAny(file, patterns))) return false;
  return !matchesAny(file, [
    /^(docs|plans|design)\//,
    /\.(md|txt)$/,
    /^crates\/kuzushi-core\/src\/(?:.*\/)?domain\//,
  ]);
}

function matchesAny(file, patterns) {
  return patterns.some((pattern) => pattern.test(file));
}

export function changedPaths(base, cwd = process.cwd()) {
  if (!/^[a-f0-9]{40,64}$/i.test(base ?? "")) return null;
  try {
    return execFileSync("git", ["diff", "--name-only", "-z", "--no-renames", `${base}...HEAD`], {
      cwd,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    })
      .split("\0")
      .filter(Boolean);
  } catch {
    // Missing history or an oversized diff must run the matrix, never skip it.
    return null;
  }
}

export function selectionOutput(selection) {
  return Object.entries({ runtime: Object.values(selection).some(Boolean), ...selection })
    .map(([name, enabled]) => `${name}=${enabled}\n`)
    .join("");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const selection = selectPlatformRuntime(changedPaths(process.env.PLATFORM_DIFF_BASE));
  const output = selectionOutput(selection);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, output);
  process.stdout.write(output);
}

import { spawnSync } from "node:child_process";
import { accessSync, constants, statSync } from "node:fs";
import { constants as osConstants } from "node:os";
import { dirname, isAbsolute } from "node:path";
import { cargoNativeBuildArgs, nativeRuntimeBinaries } from "./native-runtime-contract.mjs";

export function buildSourceRuntime(root) {
  process.stderr.write("kuzushi: checking source build…\n");
  const result = spawnSync(
    "cargo",
    [...cargoNativeBuildArgs(), "--quiet", "--message-format=json"],
    {
      cwd: root,
      encoding: "utf8",
      stdio: ["inherit", "pipe", "inherit"],
      maxBuffer: 32 * 1024 * 1024,
    },
  );
  const messages = cargoMessages(result.stdout ?? "", result.status === 0);
  requireSuccessfulBuild(result, messages);
  return requireCompleteRuntime(messages);
}

function cargoMessages(output, complete) {
  return output
    .split("\n")
    .filter((line) => line.startsWith("{"))
    .map((line) => cargoMessage(line, complete))
    .filter(Boolean);
}

function cargoMessage(line, complete) {
  try {
    return JSON.parse(line);
  } catch (error) {
    if (complete) throw new Error("Cargo returned unreadable build output.", { cause: error });
    return undefined;
  }
}

function requireSuccessfulBuild(result, messages) {
  if (result.error) throw new Error(`Could not start Cargo: ${result.error.message}`);
  if (result.status === 0) return;
  for (const item of messages.filter((item) => item.reason === "compiler-message")) {
    process.stderr.write(item.message?.rendered ?? "");
  }
  const error = new Error("Source build failed. Fix the build before launching Kuzushi.");
  error.exitCode = childExitCode(result);
  throw error;
}

export function childExitCode(result) {
  if (result.status !== null) return result.status;
  const number = osConstants.signals[result.signal];
  return Number.isInteger(number) ? 128 + number : 1;
}

export function requireCompleteRuntime(messages) {
  const binaries = new Map(
    messages.filter(isExecutableArtifact).map((item) => [item.target.name, item.executable]),
  );
  const cli = binaries.get("kuzushi");
  for (const name of nativeRuntimeBinaries) {
    requireRuntimeSibling(name, binaries.get(name), cli);
  }
  return cli;
}

function isExecutableArtifact(item) {
  return (
    item.reason === "compiler-artifact" && item.executable && item.target?.kind?.includes("bin")
  );
}

function requireRuntimeSibling(name, executable, cli) {
  if (!executable || !isAbsolute(executable)) {
    throw new Error(`Cargo did not report an executable for ${name}. No older build was launched.`);
  }
  if (!statSync(executable, { throwIfNoEntry: false })?.isFile()) {
    throw new Error(`Cargo executable is missing: ${executable}. No older build was launched.`);
  }
  accessSync(executable, constants.X_OK);
  if (dirname(executable) !== dirname(cli)) {
    throw new Error(`Cargo placed ${name} outside the CLI runtime directory.`);
  }
}

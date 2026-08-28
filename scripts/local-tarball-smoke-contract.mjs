import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";
import { nativePlatformPackage, nativePlatformPackages } from "./native-runtime-contract.mjs";

/**
 * Smoking a foreign slug is refused by default. The operator opts in per run,
 * and the opt-in still only unlocks the one pairing Apple can actually
 * translate: an Intel payload executed on Apple silicon through Rosetta 2.
 */
export const rosettaOverrideEnvVar = "KUZUSHI_SMOKE_ALLOW_ROSETTA";
export const rosettaMarkerPath = "/Library/Apple/usr/libexec/oah";
const rosettaTranslatedSlug = "darwin-x64";
const rosettaHostSlug = "darwin-arm64";
const rosettaHostArch = "arm64";

export function rosettaOverrideRequested(env = process.env) {
  return env[rosettaOverrideEnvVar] === "1";
}

/** The adapter boundary: asks the host whether Rosetta 2 is actually present. */
export function rosettaTranslationInstalled({ markerExists, probe } = {}) {
  const marker = markerExists ?? (() => existsSync(rosettaMarkerPath));
  if (marker()) return true;
  const run = probe ?? defaultRosettaProbe;
  return run();
}

/**
 * The adapter boundary: asks macOS whether this Node process is itself being
 * translated. An x64 Node on Apple silicon reports `process.arch === "x64"`,
 * which is true of the process and false of the machine underneath it.
 */
export function processIsTranslated({ platform = process.platform, probe } = {}) {
  if (platform !== "darwin") return false;
  return (probe ?? defaultTranslationProbe)();
}

/** The architecture of the machine, which a translated process misreports. */
export function machineArchitecture(nodeArch, translated) {
  return translated ? rosettaHostArch : nodeArch;
}

/**
 * npm gates `@kuzushi/darwin-x64` on `process.arch === "x64"`, so an arm64 Node
 * would install no platform package at all and smoke nothing. Refuse loudly
 * rather than pass a leg that never exercised the Intel payload.
 */
export function nodeArchitectureFailure(plan_, nodeArch) {
  if (plan_.translation !== "rosetta" || nodeArch === "x64") return null;
  return (
    `release smoke ${plan_.smokedSlug} on ${plan_.hostSlug} must run under an x64 Node, ` +
    `but this process reports ${nodeArch}; put an x64 Node prefix first on PATH`
  );
}

/**
 * Why a Rosetta-translated smoke may not run, or `null` when it may. Pure.
 */
function rosettaPlanFailure({ slug, hostSlug, platform, arch, allowRosetta, rosettaInstalled }) {
  if (slug !== rosettaTranslatedSlug || hostSlug !== rosettaHostSlug) {
    return `release smoke ${slug} cannot run on ${platform}-${arch}`;
  }
  if (!allowRosetta) {
    return `release smoke ${slug} on ${hostSlug} requires an explicit ${rosettaOverrideEnvVar}=1 opt-in`;
  }
  if (!rosettaInstalled) {
    return `release smoke ${slug} on ${hostSlug} requested Rosetta translation, but Rosetta 2 is not installed`;
  }
  return null;
}

/**
 * The one place that decides which slug a smoke run may execute, and under what
 * translation. Pure: every host fact arrives as an argument.
 */
export function smokeExecutionPlan({
  slug,
  platform,
  arch,
  allowRosetta = false,
  rosettaInstalled = false,
}) {
  if (!nativePlatformPackages.some((candidate) => candidate.slug === slug)) {
    throw new Error(`unknown release platform ${slug}`);
  }
  const hostSlug = nativePlatformPackage(platform, arch)?.slug;
  if (hostSlug === slug) return plan(hostSlug, slug, "none");
  const failure = rosettaPlanFailure({
    slug,
    hostSlug,
    platform,
    arch,
    allowRosetta,
    rosettaInstalled,
  });
  if (failure) throw new Error(failure);
  return plan(hostSlug, slug, "rosetta");
}

/** The launcher prefix that executes a translated payload, if any. */
export function translatedCommand(plan_, command, args) {
  if (plan_.translation !== "rosetta") return { command, args };
  return { command: "/usr/bin/arch", args: ["-x86_64", command, ...args] };
}

export function selectLocalTarballs(manifest, directory, slug, platform, arch, options = {}) {
  const executionPlan = smokeExecutionPlan({ slug, platform, arch, ...options });
  const root = manifest.files.find((record) => record.kind === "root-npm");
  const native = manifest.files.find(
    (record) => record.kind === "platform-npm" && record.slug === slug,
  );
  if (!root || !native) throw new Error(`release manifest is missing local tarballs for ${slug}`);
  return {
    root,
    native,
    plan: executionPlan,
    rootPath: path.join(directory, root.file),
    nativePath: path.join(directory, native.file),
  };
}

export function localConsumerManifest(version, selected) {
  return {
    name: "kuzushi-local-release-smoke",
    version: "0.0.0",
    private: true,
    dependencies: {
      kuzushi: pathToFileURL(selected.rootPath).href,
      [selected.native.name]: pathToFileURL(selected.nativePath).href,
    },
    kuzushiExpectedVersion: version,
  };
}

function plan(hostSlug, smokedSlug, translation) {
  return Object.freeze({ hostSlug, smokedSlug, translation });
}

function defaultRosettaProbe() {
  const result = spawnSync("/usr/bin/arch", ["-x86_64", "/usr/bin/true"], { stdio: "ignore" });
  return !result.error && result.status === 0;
}

function defaultTranslationProbe() {
  const result = spawnSync("/usr/sbin/sysctl", ["-in", "sysctl.proc_translated"], {
    encoding: "utf8",
  });
  return !result.error && result.stdout.trim() === "1";
}

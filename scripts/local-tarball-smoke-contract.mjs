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
  if (slug !== rosettaTranslatedSlug || hostSlug !== rosettaHostSlug) {
    throw new Error(`release smoke ${slug} cannot run on ${platform}-${arch}`);
  }
  if (!allowRosetta) {
    throw new Error(
      `release smoke ${slug} on ${hostSlug} requires an explicit ${rosettaOverrideEnvVar}=1 opt-in`,
    );
  }
  if (!rosettaInstalled) {
    throw new Error(
      `release smoke ${slug} on ${hostSlug} requested Rosetta translation, but Rosetta 2 is not installed`,
    );
  }
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

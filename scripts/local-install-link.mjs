import {
  lstatSync,
  readFileSync,
  realpathSync,
  renameSync,
  symlinkSync,
  unlinkSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

export function priorInstallationPath(packageRoot) {
  return join(dirname(packageRoot), `.${basename(packageRoot)}.before-local`);
}

export function linkCheckout(packageRoot, checkout) {
  if (pointsToCheckout(packageRoot, checkout)) return linkResult("already linked", packageRoot);
  const backup = priorInstallationPath(packageRoot);
  if (entryExists(backup))
    throw new Error(`Prior installation already saved at ${backup}; restore it first.`);
  requireInstalledPackage(packageRoot);
  renameSync(packageRoot, backup);
  try {
    symlinkSync(resolve(checkout), packageRoot, "junction");
  } catch (error) {
    if (!entryExists(packageRoot)) renameSync(backup, packageRoot);
    throw error;
  }
  return linkResult("linked", packageRoot);
}

export function restoreInstallation(packageRoot, checkout) {
  const backup = priorInstallationPath(packageRoot);
  if (!entryExists(backup)) throw new Error(`No saved installation at ${backup}.`);
  if (!pointsToCheckout(packageRoot, checkout)) {
    throw new Error(
      "The global package no longer points to this checkout; leaving it and its backup intact.",
    );
  }
  unlinkSync(packageRoot);
  try {
    renameSync(backup, packageRoot);
  } catch (error) {
    if (!entryExists(packageRoot)) symlinkSync(resolve(checkout), packageRoot, "junction");
    throw error;
  }
}

function requireInstalledPackage(packageRoot) {
  try {
    const pkg = JSON.parse(readFileSync(`${packageRoot}/package.json`, "utf8"));
    if (pkg.name === "kuzushi") return;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  throw new Error(`No Kuzushi installation at ${packageRoot}. Run npm install -g kuzushi first.`);
}

function pointsToCheckout(packageRoot, checkout) {
  if (!lstatSync(packageRoot, { throwIfNoEntry: false })?.isSymbolicLink()) return false;
  try {
    return realpathSync(packageRoot) === realpathSync(checkout);
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function entryExists(path) {
  return lstatSync(path, { throwIfNoEntry: false }) !== undefined;
}

function linkResult(state, packageRoot) {
  const backup = priorInstallationPath(packageRoot);
  return { state, backup: entryExists(backup) ? backup : undefined };
}

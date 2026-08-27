#!/usr/bin/env node

import path from "node:path";
import process from "node:process";
import { verifyReleaseManifest } from "./release-artifact-contract.mjs";

const [directoryArg, commitSha, version] = process.argv.slice(2);
if (!directoryArg || !commitSha || !version) {
  throw new Error("usage: verify-release-artifacts.mjs <directory> <full-commit-sha> <version>");
}
const manifest = verifyReleaseManifest(path.resolve(directoryArg), commitSha, version);
process.stdout.write(
  `verified ${manifest.files.length} release files for ${version} at ${commitSha}\n`,
);

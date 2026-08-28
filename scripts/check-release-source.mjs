#!/usr/bin/env node

import process from "node:process";
import { assertCleanTrackedState } from "./source-archive-contract.mjs";

const commitSha = process.argv[2];
if (!commitSha) throw new Error("usage: check-release-source.mjs <full-commit-sha>");
assertCleanTrackedState(process.cwd(), commitSha);
process.stdout.write(`release source state is clean at ${commitSha}\n`);

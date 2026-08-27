#!/usr/bin/env node

import process from "node:process";
import { createSourceArchive } from "./source-archive-contract.mjs";

const [commitSha, output] = process.argv.slice(2);
if (!commitSha || !output) {
  throw new Error("usage: export-clean-source.mjs <full-commit-sha> <output.tar.gz>");
}
const receipt = createSourceArchive({ repo: process.cwd(), commitSha, output });
process.stdout.write(`${JSON.stringify(receipt)}\n`);

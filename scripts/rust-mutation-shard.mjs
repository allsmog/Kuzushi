#!/usr/bin/env node
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

export function mutationShard(mutantCount, maxMutants, selectionHash) {
  requirePositiveInteger(mutantCount, "mutant count");
  requirePositiveInteger(maxMutants, "maximum mutants per shard");

  const count = Math.ceil(mutantCount / maxMutants);
  const index = count === 1 ? 0 : hashPrefix(selectionHash) % count;
  const selectedCount = Math.floor((mutantCount + count - 1 - index) / count);
  return { index, count, selectedCount };
}

function requirePositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
}

function hashPrefix(selectionHash) {
  const prefix = selectionHash.slice(0, 8);
  if (!/^[0-9a-f]{8}$/u.test(prefix)) {
    throw new Error("selection hash must begin with eight lowercase hexadecimal characters");
  }
  return Number.parseInt(prefix, 16);
}

function main() {
  const [rawMutantCount, rawMaxMutants, selectionHash] = process.argv.slice(2);
  if (!selectionHash || process.argv.length !== 5) {
    throw new Error("usage: rust-mutation-shard.mjs <mutant-count> <max-mutants> <selection-hash>");
  }
  const shard = mutationShard(Number(rawMutantCount), Number(rawMaxMutants), selectionHash);
  process.stdout.write(`${shard.index} ${shard.count} ${shard.selectedCount}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}

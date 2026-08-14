import assert from "node:assert/strict";
import { test } from "node:test";
import { mutationShard } from "./rust-mutation-shard.mjs";

test("mutation shards use cargo-mutants zero-based indices", () => {
  assert.deepEqual(mutationShard(27, 12, "00000002deadbeef"), {
    index: 2,
    count: 3,
    selectedCount: 9,
  });
});

test("mutation shard sizes account for an uneven final shard", () => {
  assert.equal(mutationShard(25, 12, "00000000deadbeef").selectedCount, 9);
  assert.equal(mutationShard(25, 12, "00000001deadbeef").selectedCount, 8);
  assert.equal(mutationShard(25, 12, "00000002deadbeef").selectedCount, 8);
});

test("small mutation sets stay on the unsharded zero index", () => {
  assert.deepEqual(mutationShard(12, 12, "not-needed"), {
    index: 0,
    count: 1,
    selectedCount: 12,
  });
});

test("mutation shard inputs fail closed", () => {
  assert.throws(() => mutationShard(0, 12, "00000000"), /positive integer/u);
  assert.throws(() => mutationShard(13, 12, "not-a-hash"), /eight lowercase hexadecimal/u);
});

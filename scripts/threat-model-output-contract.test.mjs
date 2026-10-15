import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { threatModelDefaultOutputDirChecks } from "./artifact-manifest-contract.mjs";

const root = new URL("../crates/kuzushi-core/src/capabilities/threat_model/", import.meta.url);
const sources = [
  "domain/tool_contract.rs",
  "adapters/build_input.rs",
  "application/deterministic_input.rs",
  "adapters/output_paths.rs",
].map((path) => readFileSync(new URL(path, root), "utf8"));

test("context output contract follows both parsers through the canonical run resolver", () => {
  assert.deepEqual(threatModelDefaultOutputDirChecks(...sources), []);
});

test("context output contract detects detached directories and parser bypasses", () => {
  for (const [index, token, expected] of [
    [1, "resolve_build_output_dir(input, ctx, flavor, &target)", "model-backed input"],
    [2, "resolve_build_output_dir(input, ctx, flavor, &target)", "deterministic input"],
    [3, "ctx.run_id()", "producing run identity"],
    [3, "flavor.default_output_dir(target, &run_id)", "output resolver must use"],
  ]) {
    const changed = [...sources];
    changed[index] = changed[index].replace(token, "detached_output()");
    assert.ok(
      threatModelDefaultOutputDirChecks(...changed).some((failure) => failure.includes(expected)),
    );
  }
});

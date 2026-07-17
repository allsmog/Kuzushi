import assert from "node:assert/strict";
import test from "node:test";
import { testCoversProductionFile } from "./crap-risk-test-mapping.mjs";

test("unrelated changed test does not cover a production file", () => {
  assert.equal(
    testCoversProductionFile(
      "crates/kuzushi-tui/src/app/session/navigation_target_story.rs",
      "crates/kuzushi-tui/src/app/tests.rs",
      "fn unrelated_snapshot_test() {}",
    ),
    false,
  );
});

test("same-context behavior test covers its production file", () => {
  assert.equal(
    testCoversProductionFile(
      "crates/kuzushi-tui/src/app/session/navigation_target_story.rs",
      "crates/kuzushi-tui/src/app/tests.rs",
      "fn target_revision_switch_is_blocked() {}",
    ),
    true,
  );
});

test("sibling Rust tests cover the sibling module", () => {
  assert.equal(
    testCoversProductionFile(
      "crates/kuzushi-core/src/run_artifacts/run_summary_store.rs",
      "crates/kuzushi-core/src/run_artifacts/tests.rs",
    ),
    true,
  );
});

test("test in another crate never grants coverage credit", () => {
  assert.equal(
    testCoversProductionFile(
      "crates/kuzushi-core/src/run_artifacts/run_summary_store.rs",
      "crates/kuzushi-tui/src/app/tests.rs",
      "fn run_summary_store_round_trip() {}",
    ),
    false,
  );
});

test("matching TypeScript test basename grants focused credit", () => {
  assert.equal(
    testCoversProductionFile("src/modules/loader.ts", "tests/modules/loader.test.ts"),
    true,
  );
});

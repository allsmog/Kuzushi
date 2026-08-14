import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function source(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), "utf8");
}

test("Windows replacement paths import OsStrExt where encode_wide is compiled", () => {
  const database = source(
    "crates/kuzushi-core/src/run_artifacts/run_history_index/sqlite_store/database.rs",
  );
  const publisher = database.match(
    /#\[cfg\(windows\)\]\npub\(super\) fn publish_replacement[\s\S]*?\n}/,
  )?.[0];
  const widePath = database.match(/#\[cfg\(windows\)\]\nfn wide_path[\s\S]*?\n}/)?.[0];

  assert.ok(publisher, "Windows replacement publisher must be present");
  assert.ok(widePath, "Windows wide path helper must be present");
  assert.doesNotMatch(publisher, /std::os::windows::ffi::OsStrExt/);
  assert.match(widePath, /use std::os::windows::ffi::OsStrExt;/);
  assert.match(widePath, /\.encode_wide\(\)/);
});

test("Windows JSONL identity validation uses centralized secure opens and stable handles", () => {
  const jsonl = source("crates/kuzushi-core/src/worker_protocol/jsonl.rs");
  const identityCheck = jsonl.match(/fn same_windows_file[\s\S]*?\n}/)?.[0];

  assert.ok(identityCheck, "Windows JSONL identity comparison must be present");
  assert.match(identityCheck, /crate::bounded_file::open_regular_file\(path\)/);
  assert.match(
    identityCheck,
    /open_regular_file\(path\)\n {8}\.map_err\(\|error\| read_error\(path, error\)\)\?/,
  );
  assert.match(identityCheck, /windows_file_identity\(&path_file\)/);
  assert.match(identityCheck, /windows_file_identity\(handle\)/);
  assert.doesNotMatch(
    jsonl,
    /OpenOptionsExt|FILE_FLAG_OPEN_REPARSE_POINT|FILE_ATTRIBUTE_REPARSE_POINT/,
  );
  assert.doesNotMatch(jsonl, /volume_serial_number\(\)|file_index\(\)/);
});

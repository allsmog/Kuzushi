import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  locallyChangedFunctions,
  vendoredTerminalBaseline,
  verifyVendoredTerminal,
} from "./vendored-terminal-baseline.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("the pinned upstream archive authenticates actual copied terminal source", () => {
  assert.match(
    vendoredTerminalBaseline(root, "third-party/crossterm/src/event/source/unix/mio.rs"),
    /struct Parser/,
  );
  assert.equal(vendoredTerminalBaseline(root, "crates/kuzushi-tui/src/app/update.rs"), null);
  assert.equal(
    vendoredTerminalBaseline(
      root,
      "third-party/crossterm/src/event/source/unix/kuzushi_parser_tests.rs",
    ),
    null,
  );
  assert.ok(verifyVendoredTerminal(root) > 50);
});

test("a replaced archive cannot define the risk baseline", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "kuzushi-upstream-checksum-"));
  try {
    mkdirSync(path.join(directory, "third-party/upstream"), { recursive: true });
    writeFileSync(path.join(directory, "third-party/upstream/crossterm-0.29.0.crate"), "altered");
    assert.throws(
      () => vendoredTerminalBaseline(directory, "third-party/crossterm/src/lib.rs"),
      /checksum mismatch/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("new or modified functions are scored even when their names match upstream", () => {
  const original = { name: "advance", source: "fn advance() { original(); }" };
  const modified = { name: "advance", source: "fn advance() { changed(); }" };
  const added = { name: "preserve_escape_prefix", source: "fn preserve_escape_prefix() {}" };
  assert.deepEqual(locallyChangedFunctions([original, modified, added], [original]), [
    modified,
    added,
  ]);
});

test("unexpected changes to unpatched upstream files fail closed", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "kuzushi-upstream-source-"));
  try {
    mkdirSync(path.join(directory, "third-party/upstream"), { recursive: true });
    mkdirSync(path.join(directory, "third-party/crossterm/src"), { recursive: true });
    copyFileSync(
      path.join(root, "third-party/upstream/crossterm-0.29.0.crate"),
      path.join(directory, "third-party/upstream/crossterm-0.29.0.crate"),
    );
    writeFileSync(path.join(directory, "third-party/crossterm/src/lib.rs"), "altered");
    assert.throws(
      () => vendoredTerminalBaseline(directory, "third-party/crossterm/src/lib.rs"),
      /Unexpected vendored terminal change/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the real risk gate enforces local complexity and size in patched upstream files", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "kuzushi-vendored-risk-"));
  const file = "third-party/crossterm/src/event/source/unix/mio.rs";
  try {
    execFileSync("git", ["init", "-q", directory]);
    mkdirSync(path.join(directory, "third-party/upstream"), { recursive: true });
    mkdirSync(path.dirname(path.join(directory, file)), { recursive: true });
    copyFileSync(
      path.join(root, "third-party/upstream/crossterm-0.29.0.crate"),
      path.join(directory, "third-party/upstream/crossterm-0.29.0.crate"),
    );
    const source = readFileSync(path.join(root, file), "utf8");
    const risky =
      "fn added_risk(x: u8) {\n" +
      [1, 2, 3, 4, 5].map((value) => `if x == ${value} { return; }`).join("\n") +
      "\n}\n";
    writeFileSync(
      path.join(directory, file),
      source.replace("#[cfg(test)]", `${risky}#[cfg(test)]`),
    );
    const result = spawnSync(process.execPath, [path.join(root, "scripts/crap-risk-gate.mjs")], {
      cwd: directory,
      encoding: "utf8",
      env: {
        ...process.env,
        KUZUSHI_CRAP_RISK_BASE_REF: "0".repeat(40),
        KUZUSHI_CRAP_RISK_FILES: file,
      },
    });
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stderr, /added_risk complexity/);
    const large = Array.from(
      { length: 70 },
      (_, index) =>
        `fn added_${index}() {\nlet a = 1;\nlet b = 2;\nlet c = a + b;\nlet _ = c;\n}\n`,
    ).join("\n");
    writeFileSync(
      path.join(directory, file),
      source.replace("#[cfg(test)]", `${large}#[cfg(test)]`),
    );
    const sizeResult = spawnSync(
      process.execPath,
      [path.join(root, "scripts/crap-risk-gate.mjs")],
      {
        cwd: directory,
        encoding: "utf8",
        env: {
          ...process.env,
          KUZUSHI_CRAP_RISK_BASE_REF: "0".repeat(40),
          KUZUSHI_CRAP_RISK_FILES: file,
        },
      },
    );
    assert.equal(sizeResult.status, 1, sizeResult.stdout + sizeResult.stderr);
    assert.match(sizeResult.stderr, /file has \d+ logical lines; limit is 300/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

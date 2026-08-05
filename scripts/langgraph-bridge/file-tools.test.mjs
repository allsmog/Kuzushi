import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileToolsForRequest } from "./file-tools.mjs";

function setupWorkspace() {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "kuzushi-filetools-")));
  const wsRoot = join(base, "ws");
  mkdirSync(join(wsRoot, "sub"), { recursive: true });
  writeFileSync(join(wsRoot, "inside.txt"), "INSIDE_TOKEN\n");
  writeFileSync(join(wsRoot, "sub", "nested.txt"), "NESTED_TOKEN\n");
  writeFileSync(join(base, "outside.txt"), "OUTSIDE_SECRET\n");
  const request = {
    toolPolicy: {
      tools: ["Read", "LS", "Glob", "Grep"],
      mcpReadRoots: [realpathSync(wsRoot)],
    },
  };
  const tools = new Map(fileToolsForRequest(request).map((built) => [built.name, built]));
  return { base, tools };
}

test("Grep cannot read outside content via a `..` glob filter", async () => {
  const { base, tools } = setupWorkspace();
  try {
    const result = await tools.get("Grep").invoke({ pattern: "OUTSIDE_SECRET", glob: "../*.txt" });
    // A leak would emit a match line naming the escaping path (e.g. `../outside.txt:1:…`).
    // The only OUTSIDE_SECRET the result may echo is the no-matches restatement of the pattern.
    assert.equal(result.includes("outside.txt"), false);
    assert.match(result, /^no matches for/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Grep matches content inside the workspace root", async () => {
  const { base, tools } = setupWorkspace();
  try {
    const result = await tools.get("Grep").invoke({ pattern: "INSIDE_TOKEN" });
    assert.match(result, /inside\.txt/);
    assert.match(result, /INSIDE_TOKEN/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Grep reaches nested in-root files while staying confined", async () => {
  const { base, tools } = setupWorkspace();
  try {
    const result = await tools.get("Grep").invoke({ pattern: "NESTED_TOKEN" });
    assert.match(result, /sub\/nested\.txt/);
    assert.match(result, /NESTED_TOKEN/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Glob cannot list outside files via a `..` pattern", async () => {
  const { base, tools } = setupWorkspace();
  try {
    const result = await tools.get("Glob").invoke({ pattern: "../*.txt" });
    assert.equal(result.includes("outside.txt"), false);
    assert.equal(result.includes("OUTSIDE_SECRET"), false);
    assert.match(result, /no files match/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Glob lists in-root files as workspace-relative paths", async () => {
  const { base, tools } = setupWorkspace();
  try {
    const result = await tools.get("Glob").invoke({ pattern: "*.txt" });
    assert.match(result, /inside\.txt/);
    assert.equal(result.includes("outside.txt"), false);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Read still blocks a `..` escape", async () => {
  const { base, tools } = setupWorkspace();
  try {
    await assert.rejects(() => tools.get("Read").invoke({ file_path: "../outside.txt" }));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Read returns the content of an in-root file", async () => {
  const { base, tools } = setupWorkspace();
  try {
    const result = await tools.get("Read").invoke({ file_path: "inside.txt" });
    assert.match(result, /INSIDE_TOKEN/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

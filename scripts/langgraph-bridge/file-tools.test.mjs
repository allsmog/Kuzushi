import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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

test("escaping symlink matches cannot consume Grep's authorized-file budget", async () => {
  const { base, tools } = setupWorkspace();
  const wsRoot = join(base, "ws");
  const outside = join(base, "outside.txt");
  writeFileSync(join(wsRoot, "zzzz.budget.txt"), "AUTHORIZED_BUDGET_TOKEN\n");
  // The old implementation sliced the first 5,000 raw glob matches before
  // confinement. An untrusted repository could therefore fill that prefix
  // with escaping symlinks and make an authorized finding disappear.
  for (let index = 0; index < 5000; index += 1) {
    symlinkSync(outside, join(wsRoot, `${String(index).padStart(4, "0")}.budget.txt`));
  }
  try {
    const result = await tools
      .get("Grep")
      .invoke({ pattern: "AUTHORIZED_BUDGET_TOKEN", glob: "*.budget.txt" });
    assert.match(result, /^zzzz\.budget\.txt:1:AUTHORIZED_BUDGET_TOKEN$/m);
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

test("Glob reports an in-root symlink by its matched path, not its realpath target", async () => {
  const { base, tools } = setupWorkspace();
  const wsRoot = join(base, "ws");
  symlinkSync(join(wsRoot, "inside.txt"), join(wsRoot, "link.txt"));
  try {
    const result = await tools.get("Glob").invoke({ pattern: "link.txt" });
    // The path that matched the pattern must be echoed back, not the resolved target.
    assert.match(result, /^link\.txt$/m);
    assert.equal(result.includes("inside.txt"), false);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Grep cites an in-root symlink by its matched path and reads through it", async () => {
  const { base, tools } = setupWorkspace();
  const wsRoot = join(base, "ws");
  symlinkSync(join(wsRoot, "inside.txt"), join(wsRoot, "link.txt"));
  try {
    const result = await tools.get("Grep").invoke({ pattern: "INSIDE_TOKEN", glob: "link.txt" });
    assert.match(result, /^link\.txt:1:INSIDE_TOKEN$/m);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Glob and Grep drop an in-root symlink whose target escapes the roots", async () => {
  const { base, tools } = setupWorkspace();
  const wsRoot = join(base, "ws");
  symlinkSync(join(base, "outside.txt"), join(wsRoot, "escape.txt"));
  try {
    // The pattern equals the escaping path, so the no-match sentence echoes it;
    // assert exact equality — a leak would instead emit a bare `escape.txt`
    // match line (Glob) or an `escape.txt:1:…` hit line (Grep).
    const globbed = await tools.get("Glob").invoke({ pattern: "escape.txt" });
    assert.equal(globbed, "no files match escape.txt");
    const grepped = await tools.get("Grep").invoke({ pattern: "OUTSIDE_SECRET", glob: "escape.txt" });
    assert.equal(grepped, "no matches for OUTSIDE_SECRET");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

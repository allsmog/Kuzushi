import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { confinedCandidates, fileToolsForRequest } from "./file-tools.mjs";

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

test("Grep terminates catastrophic regular expressions within a fixed budget", async () => {
  const { base, tools } = setupWorkspace();
  const wsRoot = join(base, "ws");
  writeFileSync(join(wsRoot, "slow.txt"), `${"a".repeat(30_000)}!\n`);
  const started = Date.now();
  try {
    await assert.rejects(
      () => tools.get("Grep").invoke({ pattern: "^(a+)+$", path: "slow.txt" }),
      /regular-expression evaluation exceeded its time budget/,
    );
    assert.ok(Date.now() - started < 5000, "catastrophic regex must not monopolize the bridge");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Grep rejects invalid regular expressions without echoing the pattern", async () => {
  const { base, tools } = setupWorkspace();
  const invalid = "[operator-secret";
  try {
    await assert.rejects(
      () => tools.get("Grep").invoke({ pattern: invalid, path: "inside.txt" }),
      (error) => {
        assert.equal(error.message, "Grep pattern is not a valid regular expression");
        assert.equal(error.message.includes(invalid), false);
        return true;
      },
    );
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Grep rejects oversized patterns before worker execution", async () => {
  const { base, tools } = setupWorkspace();
  try {
    await assert.rejects(() => tools.get("Grep").invoke({ pattern: "a".repeat(4097) }));
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

test("LS refuses a directory pathname swapped outside after authorization", async () => {
  const { base } = setupWorkspace();
  const wsRoot = join(base, "ws");
  const listed = join(wsRoot, "listed");
  const outside = join(base, "outside-dir");
  mkdirSync(listed);
  mkdirSync(outside);
  writeFileSync(join(outside, "OUTSIDE_SECRET_NAME"), "secret\n");
  const request = {
    toolPolicy: { tools: ["LS"], mcpReadRoots: [realpathSync(wsRoot)] },
  };
  const hooks = {
    afterDirectoryValidation() {
      rmSync(listed, { recursive: true });
      symlinkSync(outside, listed);
    },
  };
  const ls = fileToolsForRequest(request, hooks).find((built) => built.name === "LS");
  try {
    await assert.rejects(
      () => ls.invoke({ path: "listed" }),
      /workspace directory changed during authorization/,
    );
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Read keeps the authorized descriptor when the pathname is swapped before reading", async () => {
  const { base } = setupWorkspace();
  const wsRoot = join(base, "ws");
  const inside = join(wsRoot, "inside.txt");
  const request = {
    toolPolicy: { tools: ["Read"], mcpReadRoots: [realpathSync(wsRoot)] },
  };
  let swapped = false;
  const hooks = {
    afterFileValidation(toolName) {
      if (toolName !== "Read" || swapped) return;
      rmSync(inside);
      symlinkSync(join(base, "outside.txt"), inside);
      swapped = true;
    },
  };
  const read = fileToolsForRequest(request, hooks).find((built) => built.name === "Read");
  try {
    const result = await read.invoke({ file_path: "inside.txt" });
    assert.match(result, /INSIDE_TOKEN/);
    assert.equal(result.includes("OUTSIDE_SECRET"), false);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("Grep keeps the authorized descriptor when the pathname is swapped before reading", async () => {
  const { base } = setupWorkspace();
  const wsRoot = join(base, "ws");
  const inside = join(wsRoot, "inside.txt");
  const request = {
    toolPolicy: { tools: ["Grep"], mcpReadRoots: [realpathSync(wsRoot)] },
  };
  let swapped = false;
  const hooks = {
    afterFileValidation(toolName) {
      if (toolName !== "Grep" || swapped) return;
      rmSync(inside);
      symlinkSync(join(base, "outside.txt"), inside);
      swapped = true;
    },
  };
  const grep = fileToolsForRequest(request, hooks).find((built) => built.name === "Grep");
  try {
    const result = await grep.invoke({ pattern: "INSIDE_TOKEN|OUTSIDE_SECRET", path: "inside.txt" });
    assert.match(result, /inside\.txt:1:INSIDE_TOKEN/);
    assert.equal(result.includes("OUTSIDE_SECRET"), false);
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

test("confinement work stays bounded when every candidate is rejected", () => {
  const { base } = setupWorkspace();
  const wsRoot = join(base, "ws");
  const roots = [realpathSync(wsRoot)];
  // 25,001 nonexistent candidates all fail realpath and are rejected; the
  // inspection cap must stop the walk instead of paying for every entry.
  const matches = Array.from({ length: 25_001 }, (_, index) => `missing-${index}.txt`);
  try {
    const { kept, truncated } = confinedCandidates(matches, wsRoot, roots, 5000);
    assert.equal(kept.length, 0);
    assert.equal(truncated, true);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("an authorized candidate inside the inspection cap is still kept", () => {
  const { base } = setupWorkspace();
  const wsRoot = join(base, "ws");
  const roots = [realpathSync(wsRoot)];
  const matches = ["inside.txt", ...Array.from({ length: 25_000 }, (_, index) => `missing-${index}.txt`)];
  try {
    const { kept, truncated } = confinedCandidates(matches, wsRoot, roots, 5000);
    assert.equal(kept.length, 1);
    assert.equal(kept[0].matchedPath, join(wsRoot, "inside.txt"));
    assert.equal(truncated, true);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { preparePublicCoreWorkspace, rewriteWorkspaceManifest } from "./public-core-workspace.mjs";

const privateUrl = "https://github.com/allsmog/oxidized-joern.git";
const revision = "9ab43859f0c3342c734ff38ea6366711d216c8fd";
const names = ["cpg-analysis", "cpg-cli", "cpg-core", "cpg-incremental"];

function manifest() {
  return `[workspace]\n\n[workspace.dependencies]\n${names
    .map((name) => `${name} = { git = "${privateUrl}", rev = "${revision}" }`)
    .join("\n")}\nserde = "1"\n`;
}

function lock() {
  return `version = 4\n\n${names
    .map(
      (name, index) => `[[package]]
name = "${name}"
version = "0.${index + 1}.0"
source = "git+${privateUrl}?rev=${revision}#${revision}"
`,
    )
    .join("\n")}`;
}

test("rewrites every private source to an external local resolver stub", () => {
  const rewritten = rewriteWorkspaceManifest(manifest(), "../stubs");

  assert.doesNotMatch(rewritten, /oxidized-joern/);
  for (const name of names) {
    assert.match(rewritten, new RegExp(`${name} = \\{ path = "../stubs/${name}" \\}`));
  }
});

test("fails closed when a private dependency declaration drifts", () => {
  const drifted = manifest().replace(`rev = "${revision}"`, 'branch = "main"');

  assert.throws(
    () => rewriteWorkspaceManifest(drifted, "../stubs"),
    /one pinned private dependency line for cpg-analysis/,
  );
});

test("prepares version-matched resolver packages outside the workspace", () => {
  const root = mkdtempSync(join(tmpdir(), "kuzushi-public-core-test-"));
  const workspace = join(root, "worktree");
  const stubs = join(root, "stubs");
  try {
    mkdirSync(workspace, { recursive: true });
    writeFileSync(join(workspace, "Cargo.toml"), manifest());
    writeFileSync(join(workspace, "Cargo.lock"), lock());

    const result = preparePublicCoreWorkspace(workspace, stubs);

    assert.equal(result.packages, 4);
    assert.equal(result.stubRoot, "../stubs");
    names.forEach((name, index) => {
      const cargo = readFileSync(join(stubs, name, "Cargo.toml"), "utf8");
      assert.match(cargo, new RegExp(`name = "${name}"`));
      assert.match(cargo, new RegExp(`version = "0\\.${index + 1}\\.0"`));
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

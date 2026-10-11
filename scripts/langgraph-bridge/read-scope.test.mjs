import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileToolsForRequest } from "./file-tools.mjs";
import { READ_ONLY_SCOPE_POLICY_ID } from "./read-scope.mjs";
import { acknowledgeToolPolicy, authorizeExecutingQuery } from "./tool-policy-handshake.mjs";

function fixture() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "owned-read-membership-")));
  mkdirSync(join(root, "app", "[route]"), { recursive: true });
  mkdirSync(join(root, "shared"));
  writeFileSync(join(root, "app/[route]/allowed.rs"), "OWNED_DISCOVERY\n");
  writeFileSync(join(root, "app/unapproved.rs"), "UNAPPROVED_SOURCE\n");
  writeFileSync(join(root, "shared/context.rs"), "OWNED_CONTEXT\n");
  const files = ["app/[route]/allowed.rs", "shared/context.rs"];
  const scope = { schemaVersion: 1, files, sha256: createHash("sha256").update(JSON.stringify(files)).digest("hex") };
  const policy = { profile: READ_ONLY_SCOPE_POLICY_ID, tools: ["Read", "LS", "Glob", "Grep"], mcps: false,
    mcpsAttached: [], mcpReadRoots: [root], readScope: scope };
  const request = { cwd: root, toolPolicy: policy,
    authorization: { protocolVersion: 1, policyId: READ_ONLY_SCOPE_POLICY_ID, policy } };
  return { root, request, tools: new Map(fileToolsForRequest(request).map((tool) => [tool.name, tool])) };
}

test("scoped tools read discovery and inherited context without exposing unapproved files", async () => {
  const { root, request, tools } = fixture();
  try {
    assert.match(await tools.get("Read").invoke({ file_path: "app/[route]/allowed.rs" }), /OWNED_DISCOVERY/u);
    assert.match(await tools.get("Read").invoke({ file_path: "shared/context.rs" }), /OWNED_CONTEXT/u);
    await assert.rejects(tools.get("Read").invoke({ file_path: "app/unapproved.rs" }), /outside accepted/u);
    const listed = await tools.get("LS").invoke({ path: "app" });
    assert.match(listed, /\[route\]\//u);
    assert.ok(!listed.includes("unapproved"));
    const found = await tools.get("Glob").invoke({ pattern: "**/*.rs" });
    assert.ok(!found.includes("unapproved"));
    assert.match(found, /shared\/context.rs/u);
    const grep = await tools.get("Grep").invoke({ pattern: "UNAPPROVED_SOURCE" });
    assert.ok(!grep.includes("unapproved.rs"));
    const ack = acknowledgeToolPolicy(request).acknowledgement;
    assert.equal(ack.readScopeSha256, request.toolPolicy.readScope.sha256);
    assert.equal(authorizeExecutingQuery(request).readScopeSha256, ack.readScopeSha256);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("scoped reads reject symlink aliases and changed membership acknowledgements", async () => {
  const { root, request, tools } = fixture();
  try {
    symlinkSync(join(root, "app/[route]/allowed.rs"), join(root, "alias.rs"));
    await assert.rejects(tools.get("Read").invoke({ file_path: "alias.rs" }), /outside accepted/u);
    rmSync(join(root, "app/[route]/allowed.rs"));
    symlinkSync(join(root, "app/unapproved.rs"), join(root, "app/[route]/allowed.rs"));
    await assert.rejects(tools.get("Read").invoke({ file_path: "app/[route]/allowed.rs" }), /outside accepted/u);
    request.toolPolicy.readScope.files.push("app/unapproved.rs");
    assert.throws(() => acknowledgeToolPolicy(request), /digest/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("scoped authorization rejects missing membership and MCP authority", () => {
  const { root, request } = fixture();
  try {
    delete request.toolPolicy.readScope;
    assert.throws(() => acknowledgeToolPolicy(request), /kind/u);
    assert.throws(() => fileToolsForRequest(request), /membership/u);
    request.toolPolicy.mcps = true;
    assert.throws(() => acknowledgeToolPolicy(request), /MCP/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("scoped reads reject an in-root directory rebound to unapproved content", async () => {
  const { root, tools } = fixture();
  try {
    mkdirSync(join(root, "unapproved"));
    writeFileSync(join(root, "unapproved/allowed.rs"), "UNAPPROVED_SOURCE\n");
    renameSync(join(root, "app/[route]"), join(root, "original"));
    symlinkSync(join(root, "unapproved"), join(root, "app/[route]"));
    await assert.rejects(tools.get("Read").invoke({ file_path: "app/[route]/allowed.rs" }), /outside accepted/u);
    const grep = await tools.get("Grep").invoke({ pattern: "UNAPPROVED_SOURCE" });
    assert.ok(!grep.includes("allowed.rs:"));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("declared malformed membership cannot silently become an unscoped policy", () => {
  const { root, request } = fixture();
  try {
    for (const membership of [null, {}, { files: [] }]) {
      request.toolPolicy.readScope = membership;
      assert.throws(() => fileToolsForRequest(request), /membership/u);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

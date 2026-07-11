import { readFileSync } from "node:fs";
import { Validator } from "@cfworker/json-schema";
import { describe, expect, it } from "vitest";

const schema = JSON.parse(readFileSync("schemas/kuzushi.lock.schema.json", "utf8"));
const validator = new Validator(schema, "2020-12", false);
const digest = `sha256:${"0".repeat(64)}`;

describe("KWP lockfile schema", () => {
  it("accepts the grant spellings enforced by the Rust host", () => {
    expect(validateLock(validGrant())).toBe(true);
  });

  it.each([
    ["read-write input", { fs: [{ scope: "input", mode: "rw" }] }],
    [
      "shared MCP",
      { mcp: [{ alias: "symcc", tools: [], mode: "shared", workspace: "read-write" }] },
    ],
    [
      "scratch MCP",
      { mcp: [{ alias: "symcc", tools: [], mode: "dedicated", workspace: "scratch-only" }] },
    ],
    ["networked fuzz", { fuzz: { engines: [], network: true } }],
    ["ambient exec", { exec: [{ bin: "sh", argvAllow: [] }] }],
  ])("rejects unsupported %s grants", (_label, grant) => {
    expect(validateLock(grant)).toBe(false);
  });
});

function validateLock(grant: unknown): boolean {
  return validator.validate({
    modules: {
      [digest]: {
        moduleId: "schema-test",
        digest,
        version: "1.0.0",
        descriptorHash: digest,
        grant,
        signatureChain: [],
        revoked: false,
      },
    },
  }).valid;
}

function validGrant(): unknown {
  return {
    fs: [
      { scope: "workspace", mode: "rw", maxBytes: 1024 },
      { scope: "input", mode: "ro" },
      { scope: "module-data", mode: "rw" },
    ],
    mcp: [
      {
        alias: "symcc",
        tools: ["compile"],
        mode: "dedicated",
        workspace: "read-write",
      },
    ],
    fuzz: { engines: ["property-tests"], network: false },
    exec: [],
    initCapabilities: "fs-read",
  };
}

/**
 * Regression test for v0.21 followup M3 — `run` without args (no `.`)
 * used to error with "Missing required: target" even when the home view
 * showed an active target. Root cause: per-module DelegatingDatastores
 * register a "target" OptionSpec from the tool's JSONSchema, but the
 * shell's active target lived only in `opts.target` and never made it
 * into the `globals` Datastore that the per-module store falls through to.
 *
 * The fix: shell startup mirrors `opts.target` into `globals` (and re-mirrors
 * after `/target <path>` updates it). This test pins the fall-through:
 * a `target`-required spec on a child datastore reports no missing values
 * when the parent has it set.
 */

import { describe, expect, it } from "vitest";
import { createModuleDatastore } from "../../src/copilot/dispatcher/module-dispatcher.js";
import { Datastore } from "../../src/copilot/options.js";
import type { CopilotModule } from "../../src/modules/types.js";

function moduleWithRequiredTarget(): CopilotModule {
  return {
    id: "demo",
    displayName: "demo",
    category: "defense",
    version: "0.0.0",
    description: "demo",
    tools: [
      {
        name: "demo:run",
        description: "demo run",
        headless: true,
        inputSchema: {
          type: "object",
          required: ["target"],
          properties: {
            target: {
              type: "string",
              description: "Path to scan",
            },
          },
        },
        async execute() {
          return { ok: true, output: "" };
        },
      },
    ],
  };
}

describe("createModuleDatastore — target fall-through (M3)", () => {
  it("reports target as missing when neither layer has it", () => {
    const globals = new Datastore();
    const local = createModuleDatastore(moduleWithRequiredTarget(), globals);
    expect(local.missingRequired()).toContain("target");
  });

  it("does NOT report target as missing when globals has the value (shell-level target propagation)", () => {
    const globals = new Datastore();
    globals.set("target", "/path/to/repo", "global");
    const local = createModuleDatastore(moduleWithRequiredTarget(), globals);
    expect(local.missingRequired()).not.toContain("target");
    // and the value resolves through the delegating get():
    expect(local.get("target")).toBe("/path/to/repo");
  });

  it("a locally-set target overrides the parent value", () => {
    const globals = new Datastore();
    globals.set("target", "/parent", "global");
    const local = createModuleDatastore(moduleWithRequiredTarget(), globals);
    local.set("target", "/local", "module");
    expect(local.get("target")).toBe("/local");
  });

  it("re-syncing the parent after /target updates is reflected immediately", () => {
    const globals = new Datastore();
    const local = createModuleDatastore(moduleWithRequiredTarget(), globals);
    expect(local.missingRequired()).toContain("target");
    // simulate shell calling syncShellTargetToGlobals after /target /repo
    globals.set("target", "/repo", "global");
    expect(local.missingRequired()).not.toContain("target");
    // and clearing the active target restores the missing-required signal
    globals.unset("target", "global");
    expect(local.missingRequired()).toContain("target");
  });
});

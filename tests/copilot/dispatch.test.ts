/**
 * Smoke tests for `src/copilot/dispatch/resolve-tool.ts`.
 *
 * Locks in the routing behavior that operators rely on in the shell:
 *   - Bare action names resolve to their tool (preferring `sast:` on ties).
 *   - Focused-module shorthand takes precedence.
 *   - Positional paths are distinguished from mistyped tool names.
 *   - Unknown inputs never silently fall through.
 *
 * Two live session bugs this suite prevents from recurring:
 *   - `scan .` at top level used to resolve undefined (multiple modules
 *     exposed `scan`) → fell through to the NL agent which hallucinated a
 *     report from cached `.kuzushi/` artifacts.
 *   - `run .` inside `threat-hunt` used to resolve undefined (`.` is not
 *     a tool name) → "Unknown tool: ."
 */

import { describe, expect, it } from "vitest";
import { resolveTool, type ToolIndex } from "../../src/copilot/dispatch/resolve-tool.js";
import type { CopilotModule, ModuleTool } from "../../src/modules/types.js";

function tool(name: string): ModuleTool {
  return {
    name,
    description: `${name} description`,
    inputSchema: { type: "object", properties: {} },
    headless: true,
    async execute() {
      return { ok: true, output: "" };
    },
  };
}

function mod(id: string, toolNames: string[]): CopilotModule {
  return {
    id,
    displayName: id,
    category: "defense",
    version: "0.0.0",
    description: `${id} module`,
    tools: toolNames.map(tool),
  };
}

/**
 * Fixture registry modelled after the real CopilotCore default load-out:
 *   - `sast` umbrella with `sast:scan`
 *   - `semgrep` / `codeql` each with `scan`
 *   - `threat-hunt` with `run`
 *   - `recon` with multiple tool names (no `scan`)
 */
function buildFixtureRegistry(): ToolIndex {
  const modules: CopilotModule[] = [
    mod("sast", ["sast:scan"]),
    mod("semgrep", ["semgrep:scan"]),
    mod("codeql", ["codeql:scan"]),
    mod("threat-hunt", ["threat-hunt:run"]),
    mod("recon", ["recon:nmap", "recon:subdomain", "recon:http-fingerprint"]),
  ];

  const flat = modules.flatMap((module) => module.tools.map((t) => ({ module, tool: t })));

  return {
    resolveTool(qualifiedName) {
      return flat.find(({ tool: t }) => t.name === qualifiedName);
    },
    allTools() {
      return flat;
    },
  };
}

describe("resolveTool", () => {
  const registry = buildFixtureRegistry();

  describe("qualified module:action", () => {
    it("resolves sast:scan directly", () => {
      const r = resolveTool({ input: "sast:scan", registry });
      expect(r).toEqual({ kind: "tool", toolName: "sast:scan" });
    });

    it("returns unknown for a qualified name with no match", () => {
      const r = resolveTool({ input: "sast:no-such", registry });
      expect(r).toEqual({ kind: "unknown" });
    });
  });

  describe("focused-module shorthand", () => {
    it("maps `run` inside threat-hunt to threat-hunt:run", () => {
      const r = resolveTool({ input: "run", focusedModule: "threat-hunt", registry });
      expect(r).toEqual({ kind: "tool", toolName: "threat-hunt:run" });
    });

    it("maps `scan` inside sast to sast:scan", () => {
      const r = resolveTool({ input: "scan", focusedModule: "sast", registry });
      expect(r).toEqual({ kind: "tool", toolName: "sast:scan" });
    });

    it("falls through when the focused module has no matching tool", () => {
      // `recon` has nmap/subdomain/http-fingerprint but no `scan`. The
      // resolver should still catch the ambiguous scan across other modules
      // and prefer sast.
      const r = resolveTool({ input: "scan", focusedModule: "recon", registry });
      expect(r).toEqual({ kind: "tool", toolName: "sast:scan" });
    });
  });

  describe("bare action across modules", () => {
    it("`scan` (ambiguous across sast/semgrep/codeql) prefers sast:scan", () => {
      // The actual bug: used to return undefined and fall through to the
      // NL agent. Locking in sast preference here.
      const r = resolveTool({ input: "scan", registry });
      expect(r).toEqual({ kind: "tool", toolName: "sast:scan" });
    });

    it("a unique action name resolves without preference logic", () => {
      const r = resolveTool({ input: "nmap", registry });
      expect(r).toEqual({ kind: "tool", toolName: "recon:nmap" });
    });

    it("reports ambiguous when no sast module and multiple matches", () => {
      const noSast: ToolIndex = {
        resolveTool(qualifiedName) {
          return buildFixtureRegistry()
            .allTools()
            .filter(({ module }) => module.id !== "sast")
            .find(({ tool: t }) => t.name === qualifiedName);
        },
        allTools() {
          return buildFixtureRegistry()
            .allTools()
            .filter(({ module }) => module.id !== "sast");
        },
      };
      const r = resolveTool({ input: "scan", registry: noSast });
      expect(r.kind).toBe("ambiguous");
      if (r.kind === "ambiguous") {
        expect(r.matches.sort()).toEqual(["codeql:scan", "semgrep:scan"]);
      }
    });
  });

  describe("module-id bare word", () => {
    it("`semgrep` at top level picks the module's preferred `scan` action", () => {
      const r = resolveTool({ input: "semgrep", registry });
      expect(r).toEqual({ kind: "tool", toolName: "semgrep:scan" });
    });

    it("`threat-hunt` at top level picks the module's `run` action", () => {
      const r = resolveTool({ input: "threat-hunt", registry });
      expect(r).toEqual({ kind: "tool", toolName: "threat-hunt:run" });
    });
  });

  describe("path-like positionals", () => {
    it("`.` is reported as a path (caller binds to required option)", () => {
      const r = resolveTool({ input: ".", registry });
      expect(r).toEqual({ kind: "path", value: "." });
    });

    it("`./relative` is a path", () => {
      const r = resolveTool({ input: "./relative", registry });
      expect(r.kind).toBe("path");
    });

    it("`/abs/path` is a path", () => {
      const r = resolveTool({ input: "/abs/path", registry });
      expect(r.kind).toBe("path");
    });

    it("path check happens only after other resolutions fail", () => {
      // `scan` is an action name — must resolve to a tool even if a local
      // file named `scan` existed in the cwd.
      const r = resolveTool({ input: "scan", registry });
      expect(r.kind).toBe("tool");
    });
  });

  describe("unknown inputs", () => {
    it("typo `cluade` (not a tool, not a path) is unknown", () => {
      const r = resolveTool({ input: "cluade", registry });
      expect(r).toEqual({ kind: "unknown" });
    });

    it("empty input is unknown", () => {
      const r = resolveTool({ input: "", registry });
      expect(r).toEqual({ kind: "unknown" });
    });

    it("bare natural-language sentence is unknown (regression: no NL fallback)", () => {
      // Phrased as a single token since `resolveTool` works on pre-parsed
      // command names. Multi-token natural language is handled higher up
      // by the shell's routing layer — this guards the per-token path.
      const r = resolveTool({ input: "triage", registry });
      expect(r).toEqual({ kind: "unknown" });
    });
  });
});

import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { getCodeIntelligenceProvider } from "../../../src/analysis-support/index.js";
import { gatherContextForRoot } from "../../../src/agents/tasks/context-gatherer.js";
import { __systemsContextGathererInternals } from "../../../src/agents/tasks/systems-hunt/context.js";
import { buildSystemsSurfacePack } from "../../../src/agents/tasks/systems-hunt/helpers.js";

const { rankSystemsSurfaces, inferSurfaceKind } = __systemsContextGathererInternals;

describe("systems-context-gatherer", () => {
  it("ranks protocol and arithmetic-heavy native surfaces", async () => {
    const repoRoot = mkdtempSync(path.join(os.tmpdir(), "systems-hunt-"));
    try {
      writeFileSync(path.join(repoRoot, "CMakeLists.txt"), "project(test C)\n");
      mkdirSync(path.join(repoRoot, "src"), { recursive: true });
      writeFileSync(
        path.join(repoRoot, "src", "tcp_input.c"),
        [
          "int handle_sack(int seq, unsigned ack, int len, char *dst, char *packet) {",
          "  if (seq < (int)ack && ack == 0xFFFF) {",
          "    memcpy(dst, packet, len);",
          "  }",
          "  return 0;",
          "}",
          "__stack_chk_fail();",
        ].join("\n"),
      );

      const context = await gatherContextForRoot(repoRoot);
      const surfaces = await rankSystemsSurfaces(
        context.fileIndex,
        context.repoContext,
        repoRoot,
        5,
      );

      expect(surfaces.length).toBeGreaterThan(0);
      expect(surfaces[0].kind).toBe("protocol-parser");
      expect(surfaces[0].domains).toEqual(
        expect.arrayContaining(["protocol-parser", "integer-boundary", "unsafe-memory"]),
      );
      expect(surfaces[0].hardeningSignals.join(" ")).toContain("__stack_chk_fail");
    } finally {
      rmSync(repoRoot, { recursive: true, force: true });
    }
  });

  it("infers hypervisor and unsafe surfaces from native hints", () => {
    expect(inferSurfaceKind("src/vmm/guest_mem.rs", "unsafe { ptr::write(dst, val); }", "unsafe-memory"))
      .toBe("hypervisor-boundary");
    expect(inferSurfaceKind("src/codec/h264_slice.c", "slice_count++", "protocol-parser"))
      .toBe("codec-parser");
  });

  it("builds deterministic surface packs with related files and probe sites", async () => {
    const repoRoot = mkdtempSync(path.join(os.tmpdir(), "systems-hunt-pack-"));
    try {
      writeFileSync(path.join(repoRoot, "CMakeLists.txt"), "project(test C)\n");
      mkdirSync(path.join(repoRoot, "src"), { recursive: true });
      writeFileSync(
        path.join(repoRoot, "src", "rpc_auth.c"),
        [
          "static int decode_auth(unsigned short len, unsigned short type, char *dst, char *src) {",
          "  if ((int)len < 0 || type == 0xFFFF) return -1;",
          "  memcpy(dst, src, len);",
          "  return 0;",
          "}",
          "",
          "int handle_request(unsigned short len, unsigned short type, char *dst, char *src) {",
          "  return decode_auth(len, type, dst, src);",
          "}",
          "__stack_chk_fail();",
        ].join("\n"),
      );

      const context = await gatherContextForRoot(repoRoot);
      const surfaces = await rankSystemsSurfaces(context.fileIndex, context.repoContext, repoRoot, 5);
      const provider = await getCodeIntelligenceProvider(repoRoot);
      const pack = await buildSystemsSurfacePack({
        repoRoot,
        fileIndex: context.fileIndex,
        surface: surfaces[0],
        provider,
        surfacePackDepth: 4,
        enableCodeqlTemplates: true,
        codeqlDbPath: path.join(repoRoot, ".kuzushi", "codeql-db"),
      });

      expect(pack.anchorSymbol).toBeTruthy();
      expect(pack.relatedFiles).toContain("src/rpc_auth.c");
      expect(pack.compareCastSites.length).toBeGreaterThan(0);
      expect(pack.sentinelConstants.some((entry) => entry.snippet.includes("0xFFFF"))).toBe(true);
      expect(pack.allocationCopySites.some((entry) => entry.snippet.includes("memcpy"))).toBe(true);
      expect(pack.hardeningSites.some((entry) => entry.snippet.includes("__stack_chk_fail"))).toBe(true);
      expect(pack.helperTemplates.map((template) => template.id)).toEqual(
        expect.arrayContaining(["signed-wraparound", "rpc-xdr-length", "hardening-presence"]),
      );
    } finally {
      rmSync(repoRoot, { recursive: true, force: true });
    }
  });
});

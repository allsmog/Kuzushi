import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { gatherContextForRoot } from "../../../src/agents/tasks/context-gatherer.js";
import { __systemsContextGathererInternals } from "../../../src/agents/tasks/systems-hunt/context.js";

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
});


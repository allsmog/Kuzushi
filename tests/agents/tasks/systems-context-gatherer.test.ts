import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { gatherContextForRoot } from "../../../src/agents/tasks/context-gatherer.js";
import { __systemsContextGathererInternals } from "../../../src/agents/tasks/systems-hunt/context.js";
import { buildSystemsSurfacePack } from "../../../src/agents/tasks/systems-hunt/helpers.js";
import { getCodeIntelligenceProvider } from "../../../src/analysis-support/index.js";

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
    expect(
      inferSurfaceKind("src/vmm/guest_mem.rs", "unsafe { ptr::write(dst, val); }", "unsafe-memory"),
    ).toBe("hypervisor-boundary");
    expect(inferSurfaceKind("src/codec/h264_slice.c", "slice_count++", "protocol-parser")).toBe(
      "codec-parser",
    );
  });

  it("ranks resource provenance surfaces and builds aliasing evidence packs", async () => {
    const repoRoot = mkdtempSync(path.join(os.tmpdir(), "systems-hunt-rp-"));
    try {
      writeFileSync(path.join(repoRoot, "CMakeLists.txt"), "project(resource_provenance C)\n");
      mkdirSync(path.join(repoRoot, "src", "crypto"), { recursive: true });
      writeFileSync(
        path.join(repoRoot, "src", "crypto", "algif_aead.c"),
        [
          "struct page { int dirty; };",
          "struct scatterlist { struct page *page; unsigned int length; };",
          "struct aead_request { struct scatterlist *src; struct scatterlist *dst; unsigned int assoclen; unsigned int cryptlen; unsigned int authsize; };",
          "static void sg_chain(struct scatterlist *head, int nents, struct scatterlist *tail) { (void)head; (void)nents; (void)tail; }",
          "static struct page *sg_page(struct scatterlist *sg) { return sg->page; }",
          "static void aead_request_set_crypt(struct aead_request *req, struct scatterlist *src, struct scatterlist *dst, unsigned int len, int iv) { req->src = src; req->dst = dst; }",
          "static void scatterwalk_map_and_copy(char *tag, struct scatterlist *dst, unsigned int off, unsigned int len, int out) { if (out) dst->page->dirty = 1; }",
          "int algif_aead_recvmsg(struct aead_request *req, struct scatterlist *page_cache_sg, char *tag) {",
          "  int family = AF_ALG;",
          "  struct pipe_buffer *pipe = 0;",
          "  req->src = page_cache_sg;",
          "  req->dst = req->src;",
          "  sg_chain(req->dst, 1, page_cache_sg);",
          "  aead_request_set_crypt(req, req->src, req->dst, req->cryptlen, 0);",
          "  scatterwalk_map_and_copy(tag, req->dst, req->assoclen + req->cryptlen, req->authsize, 1);",
          "  return -74;",
          "}",
          "int splice_to_algif(void) { return splice(0, 0, 1, 0, 4096, 0); }",
        ].join("\n"),
      );

      const context = await gatherContextForRoot(repoRoot);
      const surfaces = await rankSystemsSurfaces(
        context.fileIndex,
        context.repoContext,
        repoRoot,
        5,
      );
      const surface = surfaces.find((candidate) => candidate.kind === "resource-provenance");
      expect(surface).toBeTruthy();
      expect(surface!.domains).toContain("resource-provenance");
      expect(surface!.attackerControlledFields).toEqual(
        expect.arrayContaining(["src", "dst", "authsize"]),
      );

      const provider = await getCodeIntelligenceProvider(repoRoot);
      const pack = await buildSystemsSurfacePack({
        repoRoot,
        fileIndex: context.fileIndex,
        surface: surface!,
        provider,
        surfacePackDepth: 4,
        enableCodeqlTemplates: false,
      });

      expect(pack.resourceProvenanceSites.length).toBeGreaterThan(0);
      expect(pack.aliasingSites.length).toBeGreaterThan(0);
      expect(pack.scratchWriteSites.length).toBeGreaterThan(0);
      expect(pack.failureSideEffectSites.length).toBeGreaterThan(0);
      expect(pack.provenanceFacts.map((fact) => fact.state)).toEqual(
        expect.arrayContaining([
          "PIPE_PAGE_SHARED",
          "SG_SHARED",
          "REQ_ALIAS_MUST",
          "MUTATED_SHARED",
          "FAILED_AFTER_MUTATION",
        ]),
      );
      expect(pack.provenanceFacts.some((fact) => fact.strength === "strong")).toBe(true);
      expect(pack.provenanceSummaries.map((summary) => summary.functionName)).toEqual(
        expect.arrayContaining(["algif_aead_recvmsg", "scatterwalk_map_and_copy"]),
      );
      expect(
        pack.provenanceSummaries.some(
          (summary) => summary.aliasBehavior !== "none" || summary.writesThroughSharedAlias,
        ),
      ).toBe(true);
      expect(pack.provenanceChains.some((chain) => chain.status === "complete")).toBe(true);
      expect(pack.helperTemplates.map((template) => template.id)).toEqual(
        expect.arrayContaining([
          "shared-backing-resource",
          "in-place-writable-alias",
          "scratch-write-boundary",
          "failure-side-effect",
        ]),
      );
    } finally {
      rmSync(repoRoot, { recursive: true, force: true });
    }
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
      const surfaces = await rankSystemsSurfaces(
        context.fileIndex,
        context.repoContext,
        repoRoot,
        5,
      );
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
      expect(pack.hardeningSites.some((entry) => entry.snippet.includes("__stack_chk_fail"))).toBe(
        true,
      );
      expect(pack.helperTemplates.map((template) => template.id)).toEqual(
        expect.arrayContaining(["signed-wraparound", "rpc-xdr-length", "hardening-presence"]),
      );
    } finally {
      rmSync(repoRoot, { recursive: true, force: true });
    }
  });
});

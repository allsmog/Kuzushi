import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  __crashInternals,
  collectUniqueCrashes,
  describeCrash,
  findCrashFiles,
} from "../../src/fuzz/crashes.js";

function makeDir(): string {
  return mkdtempSync(path.join(os.tmpdir(), "kuzushi-crashes-test-"));
}

describe("fuzz/crashes helpers", () => {
  it("isCrashFilename recognizes libFuzzer/AFL/ASan-flavored names", () => {
    const ok = (name: string) => expect(__crashInternals.isCrashFilename(name)).toBe(true);
    const no = (name: string) => expect(__crashInternals.isCrashFilename(name)).toBe(false);
    ok("crash-deadbeef");
    ok("id:000042,src:000001");
    ok("SIGSEGV-abc123");
    ok("oom-zzz");
    ok("leak-xyz");
    ok("timeout-a");
    no("corpus-seed-1");
    no("README.md");
    no("result.json");
  });

  it("sanitizeStackFrames extracts the top frames from ASan stack traces", () => {
    const stack = `
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead
    #0 0x00007ffff70 in do_parse /src/parser.c:42:11
    #1 0x00007ffff80 in handle_frame /src/frame.c:11:3
    #2 0x00007ffff90 in main /src/main.c:100:5
    `.trim();
    const frames = __crashInternals.sanitizeStackFrames(stack);
    expect(frames).toEqual(["do_parse", "handle_frame", "main"]);
  });

  it("computeStackHash returns a stable digest for identical frames", () => {
    const a = __crashInternals.computeStackHash(["parse", "handle", "main"]);
    const b = __crashInternals.computeStackHash(["parse", "handle", "main"]);
    expect(a).toEqual(b);
    const c = __crashInternals.computeStackHash(["different", "frames", "here"]);
    expect(c).not.toEqual(a);
  });

  it("extractSignature picks a useful line", () => {
    const stack = "==12345==ERROR: AddressSanitizer: heap-buffer-overflow";
    expect(__crashInternals.extractSignature(stack)).toContain("AddressSanitizer");
  });

  it("describeCrash + collectUniqueCrashes dedupe by stack hash", () => {
    const dir = makeDir();
    try {
      // Two crashes with DIFFERENT content but the SAME stack.
      const stack = [
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow",
        "    #0 0xa in parse_header /src/parser.c:42",
        "    #1 0xb in main /src/main.c:10",
      ].join("\n");

      const crash1 = path.join(dir, "crash-aaaa");
      writeFileSync(crash1, Buffer.from([0x01, 0x02, 0x03]));
      writeFileSync(`${crash1}.log`, stack);

      const crash2 = path.join(dir, "crash-bbbb");
      writeFileSync(crash2, Buffer.from([0x04, 0x05, 0x06, 0x07]));
      writeFileSync(`${crash2}.log`, stack);

      // A third crash with a DIFFERENT stack should NOT dedupe
      const differentStack = [
        "==2==ERROR: AddressSanitizer: heap-use-after-free",
        "    #0 0xa in decode_chunk /src/decoder.c:77",
      ].join("\n");
      const crash3 = path.join(dir, "crash-cccc");
      writeFileSync(crash3, Buffer.from([0xff, 0xff]));
      writeFileSync(`${crash3}.log`, differentStack);

      // Nested AFL-style layout
      mkdirSync(path.join(dir, "default", "crashes"), { recursive: true });
      const crash4 = path.join(dir, "default", "crashes", "id:000001,src:000000");
      writeFileSync(crash4, Buffer.from([0x10, 0x20]));

      const found = findCrashFiles(dir).sort();
      expect(found).toHaveLength(4);

      const unique = collectUniqueCrashes(dir);
      // crashes 1 and 2 collapse into one; crashes 3 and 4 stand alone.
      expect(unique).toHaveLength(3);

      const described = describeCrash(crash1);
      expect(described.stackHash).toBeDefined();
      expect(described.signature).toContain("AddressSanitizer");
      expect(described.contentHash).toMatch(/^[0-9a-f]{64}$/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("collectUniqueCrashes returns empty when directory is missing", () => {
    const result = collectUniqueCrashes("/definitely/does/not/exist/here");
    expect(result).toEqual([]);
  });
});

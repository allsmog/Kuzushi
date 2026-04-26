import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { runSemgrep } from "../../src/scanners/run-semgrep.js";

describe("runSemgrep abort handling", () => {
  it("kills the scanner and suppresses late stderr after abort", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "kuzushi-semgrep-abort-"));
    const fakeScanner = path.join(dir, "fake-semgrep.sh");
    writeFileSync(
      fakeScanner,
      [
        "#!/bin/sh",
        "trap '' TERM",
        "sleep 0.2",
        "echo '[semgrep] late leak after abort' >&2",
        "sleep 5",
      ].join("\n"),
      "utf8",
    );
    chmodSync(fakeScanner, 0o755);

    const writeSpy = vi.spyOn(process.stderr, "write").mockImplementation((() => true) as never);
    const controller = new AbortController();

    try {
      const promise = runSemgrep(
        dir,
        { severity: [], excludePatterns: [], fresh: false },
        fakeScanner,
        "auto",
        { signal: controller.signal },
      );
      setTimeout(() => controller.abort(), 50);

      await expect(promise).rejects.toMatchObject({ name: "AbortError" });
      const written = writeSpy.mock.calls
        .map(([chunk]) => (Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk)))
        .join("");
      expect(written).not.toContain("late leak after abort");
    } finally {
      writeSpy.mockRestore();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

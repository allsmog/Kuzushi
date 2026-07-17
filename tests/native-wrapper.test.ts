import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe.skipIf(process.platform === "win32")("native wrapper exit truth", () => {
  it("maps a signal-killed native child to a nonzero shell status", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "kuzushi-wrapper-"));
    tempDirs.push(directory);
    const binary = path.join(directory, "kuzushi");
    writeFileSync(binary, "#!/bin/sh\nkill -TERM $$\n", "utf8");
    chmodSync(binary, 0o755);

    const result = spawnSync(process.execPath, [path.resolve("bin/kuzushi-rs.mjs"), "--version"], {
      encoding: "utf8",
      env: { ...process.env, KUZUSHI_NATIVE_BIN: binary },
    });

    expect(result.status).toBe(143);
    expect(result.stderr).toContain("terminated by SIGTERM");
  });
});

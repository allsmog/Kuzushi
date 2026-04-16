import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { NativeAdapter } from "../../../src/discovery/adapters/native-adapter.js";

const tempDirs: string[] = [];
const adapter = new NativeAdapter();

function makeTempRoot(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-native-adapter-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("NativeAdapter", () => {
  it("discovers SConstruct at root", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "SConstruct"), "env = Environment()", "utf-8");

    const nodes = await adapter.discover(root, 8);

    expect(nodes).toHaveLength(1);
    expect(nodes[0].path).toBe(".");
    expect(nodes[0].language).toBe("C/C++");
    expect(nodes[0].buildSystem).toBe("SConstruct");
  });

  it("discovers SConstruct in subdirectory", async () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "native", "core"), { recursive: true });
    writeFileSync(path.join(root, "native", "core", "SConstruct"), "env = Environment()", "utf-8");

    const nodes = await adapter.discover(root, 8);

    expect(nodes).toHaveLength(1);
    expect(nodes[0].path).toBe("native/core");
  });

  it("returns empty when no SConstruct", async () => {
    const root = makeTempRoot();

    const nodes = await adapter.discover(root, 8);

    expect(nodes).toHaveLength(0);
  });
});

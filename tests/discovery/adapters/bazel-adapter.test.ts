import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { BazelAdapter } from "../../../src/discovery/adapters/bazel-adapter.js";

const tempDirs: string[] = [];
const adapter = new BazelAdapter();

function makeTempRoot(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-bazel-adapter-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("BazelAdapter", () => {
  it("discovers BUILD.bazel packages with production rules", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "WORKSPACE.bazel"), "", "utf-8");

    mkdirSync(path.join(root, "src", "server"), { recursive: true });
    writeFileSync(path.join(root, "src", "server", "BUILD.bazel"), 'cc_binary(\n  name = "server",\n)\n', "utf-8");

    mkdirSync(path.join(root, "src", "lib"), { recursive: true });
    writeFileSync(path.join(root, "src", "lib", "BUILD.bazel"), 'go_library(\n  name = "lib",\n)\n', "utf-8");

    const nodes = await adapter.discover(root, 8);

    const container = nodes.find((n) => n.isContainer);
    expect(container).toBeDefined();
    expect(container!.containerKind).toBe("bazel-workspace");

    const children = nodes.filter((n) => !n.isContainer);
    expect(children).toHaveLength(2);

    const server = children.find((c) => c.path === "src/server");
    expect(server?.language).toBe("C++");

    const lib = children.find((c) => c.path === "src/lib");
    expect(lib?.language).toBe("Go");
  });

  it("skips test-only packages", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "WORKSPACE"), "", "utf-8");

    mkdirSync(path.join(root, "src", "app"), { recursive: true });
    writeFileSync(path.join(root, "src", "app", "BUILD"), 'cc_binary(name = "app")\n', "utf-8");

    mkdirSync(path.join(root, "test", "app"), { recursive: true });
    writeFileSync(path.join(root, "test", "app", "BUILD"), 'cc_test(name = "app_test")\n', "utf-8");

    const nodes = await adapter.discover(root, 8);

    const children = nodes.filter((n) => !n.isContainer);
    expect(children).toHaveLength(1);
    expect(children[0].path).toBe("src/app");
  });

  it("collapses dense subtrees into single module", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "WORKSPACE.bazel"), "", "utf-8");

    // Create 20 BUILD packages under src/cpp — exceeds threshold of 15
    for (let i = 0; i < 20; i++) {
      const dir = path.join(root, "src", "cpp", `pkg-${i}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(path.join(dir, "BUILD.bazel"), `cc_library(name = "pkg-${i}")\n`, "utf-8");
    }

    // Create 3 BUILD packages under src/go — below threshold
    for (let i = 0; i < 3; i++) {
      const dir = path.join(root, "src", "go", `svc-${i}`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(path.join(dir, "BUILD.bazel"), `go_binary(name = "svc-${i}")\n`, "utf-8");
    }

    const nodes = await adapter.discover(root, 8);
    const children = nodes.filter((n) => !n.isContainer);

    // src/cpp collapsed to 1 module, src/go kept as 3 individual modules
    expect(children).toHaveLength(4);
    expect(children.some((c) => c.path === "src/cpp")).toBe(true);
    expect(children.filter((c) => c.path.startsWith("src/go")).length).toBe(3);
    // Collapsed module picks dominant language
    expect(children.find((c) => c.path === "src/cpp")!.language).toBe("C++");
  });

  it("returns empty without workspace marker", async () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "src"), { recursive: true });
    writeFileSync(path.join(root, "src", "BUILD"), 'cc_binary(name = "x")\n', "utf-8");

    const nodes = await adapter.discover(root, 8);

    expect(nodes).toHaveLength(0);
  });
});

import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { GoAdapter } from "../../../src/discovery/adapters/go-adapter.js";

const tempDirs: string[] = [];
const adapter = new GoAdapter();

function makeTempRoot(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-go-adapter-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("GoAdapter", () => {
  it("discovers go.work members", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "go.work"), "go 1.22\n\nuse (\n\tservices/api\n\tservices/web\n)\n", "utf-8");

    mkdirSync(path.join(root, "services", "api"), { recursive: true });
    writeFileSync(path.join(root, "services", "api", "go.mod"), "module example.com/api\n\ngo 1.22\n", "utf-8");

    mkdirSync(path.join(root, "services", "web"), { recursive: true });
    writeFileSync(path.join(root, "services", "web", "go.mod"), "module example.com/web\n\ngo 1.22\n", "utf-8");

    const nodes = await adapter.discover(root, 8);

    const container = nodes.find((n) => n.isContainer);
    expect(container).toBeDefined();
    expect(container!.containerKind).toBe("go-workspace");
    expect(container!.childPaths).toContain("services/api");
    expect(container!.childPaths).toContain("services/web");

    const children = nodes.filter((n) => !n.isContainer);
    expect(children).toHaveLength(2);
    expect(children.every((c) => c.language === "Go")).toBe(true);
  });

  it("discovers standalone go.mod without go.work", async () => {
    const root = makeTempRoot();
    mkdirSync(path.join(root, "cmd", "tool"), { recursive: true });
    writeFileSync(path.join(root, "cmd", "tool", "go.mod"), "module example.com/tool\n\ngo 1.22\n", "utf-8");

    const nodes = await adapter.discover(root, 8);

    expect(nodes).toHaveLength(1);
    expect(nodes[0].isContainer).toBe(false);
    expect(nodes[0].path).toBe("cmd/tool");
    expect(nodes[0].name).toBe("tool");
  });

  it("extracts module name from go.mod", async () => {
    const root = makeTempRoot();
    writeFileSync(path.join(root, "go.mod"), "module github.com/org/myproject\n\ngo 1.22\n", "utf-8");

    const nodes = await adapter.discover(root, 8);

    expect(nodes[0].name).toBe("myproject");
  });

  it("returns empty when no go files", async () => {
    const root = makeTempRoot();

    const nodes = await adapter.discover(root, 8);

    expect(nodes).toHaveLength(0);
  });
});

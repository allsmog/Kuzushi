import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { MsvsAdapter } from "../../../src/discovery/adapters/msvs-adapter.js";

const tempDirs: string[] = [];
const adapter = new MsvsAdapter();

function makeTempRoot(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-msvs-adapter-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("MsvsAdapter", () => {
  it("discovers .sln with .csproj references", async () => {
    const root = makeTempRoot();
    const slnContent = [
      "Microsoft Visual Studio Solution File",
      'Project("{FAE04EC0}") = "MyApp", "src\\MyApp\\MyApp.csproj", "{GUID1}"',
      "EndProject",
      'Project("{FAE04EC0}") = "MyLib", "src\\MyLib\\MyLib.csproj", "{GUID2}"',
      "EndProject",
    ].join("\n");
    writeFileSync(path.join(root, "MySolution.sln"), slnContent, "utf-8");

    mkdirSync(path.join(root, "src", "MyApp"), { recursive: true });
    writeFileSync(path.join(root, "src", "MyApp", "MyApp.csproj"), "<Project></Project>", "utf-8");

    mkdirSync(path.join(root, "src", "MyLib"), { recursive: true });
    writeFileSync(path.join(root, "src", "MyLib", "MyLib.csproj"), "<Project></Project>", "utf-8");

    const nodes = await adapter.discover(root, 8);

    const container = nodes.find((n) => n.isContainer);
    expect(container).toBeDefined();
    expect(container!.containerKind).toBe("solution");
    expect(container!.name).toBe("MySolution");

    const children = nodes.filter((n) => !n.isContainer);
    expect(children).toHaveLength(2);
    expect(children.map((c) => c.name).sort()).toEqual(["MyApp", "MyLib"]);
    expect(children.every((c) => c.language === "C#")).toBe(true);
    expect(children.every((c) => c.buildSystem === ".csproj")).toBe(true);
  });

  it("discovers .vcxproj references as C++", async () => {
    const root = makeTempRoot();
    const slnContent = [
      "Microsoft Visual Studio Solution File",
      'Project("{8BC9CEB8}") = "NativeLib", "native\\NativeLib.vcxproj", "{GUID1}"',
      "EndProject",
    ].join("\n");
    writeFileSync(path.join(root, "Native.sln"), slnContent, "utf-8");

    mkdirSync(path.join(root, "native"), { recursive: true });
    writeFileSync(path.join(root, "native", "NativeLib.vcxproj"), "<Project></Project>", "utf-8");

    const nodes = await adapter.discover(root, 8);

    const child = nodes.find((n) => !n.isContainer);
    expect(child).toBeDefined();
    expect(child!.language).toBe("C++");
    expect(child!.buildSystem).toBe(".vcxproj");
  });

  it("skips missing project files", async () => {
    const root = makeTempRoot();
    const slnContent = 'Project("{FAE04EC0}") = "Ghost", "ghost\\Ghost.csproj", "{GUID}"';
    writeFileSync(path.join(root, "Test.sln"), slnContent, "utf-8");
    // Don't create the ghost directory

    const nodes = await adapter.discover(root, 8);

    // No container emitted because no valid children
    expect(nodes.filter((n) => n.isContainer)).toHaveLength(0);
  });

  it("returns empty when no .sln files", async () => {
    const root = makeTempRoot();

    const nodes = await adapter.discover(root, 8);

    expect(nodes).toHaveLength(0);
  });
});

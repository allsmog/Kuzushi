import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { RustAdapter } from "../../../src/discovery/adapters/rust-adapter.js";

const tempDirs: string[] = [];
const adapter = new RustAdapter();

function makeTempRoot(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-rust-adapter-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("RustAdapter", () => {
  it("discovers Cargo workspace members", async () => {
    const root = makeTempRoot();
    writeFileSync(
      path.join(root, "Cargo.toml"),
      ["[workspace]", 'members = ["crates/core", "crates/cli"]'].join("\n"),
      "utf-8",
    );

    mkdirSync(path.join(root, "crates", "core"), { recursive: true });
    writeFileSync(
      path.join(root, "crates", "core", "Cargo.toml"),
      '[package]\nname = "mycore"\n',
      "utf-8",
    );

    mkdirSync(path.join(root, "crates", "cli"), { recursive: true });
    writeFileSync(
      path.join(root, "crates", "cli", "Cargo.toml"),
      '[package]\nname = "mycli"\n',
      "utf-8",
    );

    const nodes = await adapter.discover(root, 8);

    const container = nodes.find((n) => n.isContainer);
    expect(container).toBeDefined();
    expect(container!.containerKind).toBe("cargo-workspace");
    expect(container!.childPaths.sort()).toEqual(["crates/cli", "crates/core"]);

    const children = nodes.filter((n) => !n.isContainer);
    expect(children).toHaveLength(2);
    expect(children.every((c) => c.language === "Rust")).toBe(true);
    expect(children.map((c) => c.name).sort()).toEqual(["mycli", "mycore"]);
  });

  it("discovers standalone crate", async () => {
    const root = makeTempRoot();
    writeFileSync(
      path.join(root, "Cargo.toml"),
      '[package]\nname = "solo"\nversion = "0.1.0"\n',
      "utf-8",
    );

    const nodes = await adapter.discover(root, 8);

    expect(nodes).toHaveLength(1);
    expect(nodes[0].isContainer).toBe(false);
    expect(nodes[0].name).toBe("solo");
    expect(nodes[0].path).toBe(".");
  });

  it("returns empty when no Cargo.toml", async () => {
    const root = makeTempRoot();

    const nodes = await adapter.discover(root, 8);

    expect(nodes).toHaveLength(0);
  });
});

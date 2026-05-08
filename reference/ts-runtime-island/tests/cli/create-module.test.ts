import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createModule, isValidRank, isValidTemplate } from "../../src/cli/create-module.js";

describe("create-module scaffolder", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(path.join(tmpdir(), "kzs-scaffold-"));
  });
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("writes the full file set", () => {
    const result = createModule({
      id: "my-mod",
      template: "offense",
      targetDir: tmp,
      hostVersion: "0.20.0",
    });
    const expected = [
      "module.manifest.json",
      "package.json",
      "tsconfig.json",
      "src/index.ts",
      "src/index.test.ts",
      "README.md",
    ];
    for (const rel of expected) {
      expect(existsSync(path.join(result.moduleDir, rel))).toBe(true);
    }
  });

  it("emits kuzushiSdkVersion and $schema in the manifest", () => {
    const result = createModule({
      id: "my-mod",
      template: "offense",
      targetDir: tmp,
      hostVersion: "0.20.0",
    });
    const manifest = JSON.parse(
      readFileSync(path.join(result.moduleDir, "module.manifest.json"), "utf-8"),
    ) as Record<string, unknown>;
    expect(manifest.kuzushiSdkVersion).toBe("0.20.0");
    expect(typeof manifest.$schema).toBe("string");
    expect(String(manifest.$schema)).toContain("module.manifest.schema.json");
    expect(manifest.id).toBe("my-mod");
    expect(manifest.category).toBe("offense");
  });

  it("honors a custom --schema-url", () => {
    const result = createModule({
      id: "my-mod",
      template: "intel",
      targetDir: tmp,
      hostVersion: "0.20.0",
      schemaUrl: "https://example.com/schema.json",
    });
    const manifest = JSON.parse(
      readFileSync(path.join(result.moduleDir, "module.manifest.json"), "utf-8"),
    ) as { $schema?: string };
    expect(manifest.$schema).toBe("https://example.com/schema.json");
  });

  it("pins kuzushi as a peer-dep by default and caret-pins to host major", () => {
    const result = createModule({
      id: "my-mod",
      template: "defense",
      targetDir: tmp,
      hostVersion: "0.20.3",
    });
    const pkg = JSON.parse(readFileSync(path.join(result.moduleDir, "package.json"), "utf-8")) as {
      peerDependencies?: Record<string, string>;
      peerDependenciesMeta?: Record<string, { optional: boolean }>;
      devDependencies?: Record<string, string>;
    };
    expect(pkg.peerDependencies?.kuzushi).toBe("^0.20.3");
    expect(pkg.peerDependenciesMeta?.kuzushi?.optional).toBe(false);
    expect(pkg.devDependencies?.kuzushi).toBe("0.20.3");
  });

  it("omits peer-deps when --skip-peer-deps is set", () => {
    const result = createModule({
      id: "my-mod",
      template: "offense",
      targetDir: tmp,
      hostVersion: "0.20.0",
      skipPeerDeps: true,
    });
    const pkg = JSON.parse(
      readFileSync(path.join(result.moduleDir, "package.json"), "utf-8"),
    ) as Record<string, unknown>;
    expect(pkg.peerDependencies).toBeUndefined();
    expect(pkg.peerDependenciesMeta).toBeUndefined();
  });

  it("generated src/index.ts uses defineModule + defineTool from kuzushi/modules", () => {
    const result = createModule({
      id: "my-mod",
      template: "offense",
      targetDir: tmp,
      hostVersion: "0.20.0",
    });
    const code = readFileSync(path.join(result.moduleDir, "src/index.ts"), "utf-8");
    expect(code).toContain('from "kuzushi/modules"');
    expect(code).toContain("defineModule");
    expect(code).toContain('defineTool<"my-mod">');
    expect(code).toContain("ctx.reportActivity");
    expect(code).toContain("ctx.logger");
    expect(code).toContain('ctx.host?.capabilities.has("workspace")');
    expect(code).toContain('name: "my-mod:recon"');
    expect(code).toContain("headless: true");
  });

  it("generated test uses kuzushi/testing helpers", () => {
    const result = createModule({
      id: "my-mod",
      template: "intel",
      targetDir: tmp,
      hostVersion: "0.20.0",
    });
    const code = readFileSync(path.join(result.moduleDir, "src/index.test.ts"), "utf-8");
    expect(code).toContain('from "kuzushi/testing"');
    expect(code).toContain("expectModuleShape");
    expect(code).toContain("assertToolResult");
    expect(code).toContain("createMockToolContext");
    expect(code).toContain('name === "my-mod:lookup"');
  });

  it("reflects --rank in the generated module", () => {
    const result = createModule({
      id: "my-mod",
      template: "offense",
      targetDir: tmp,
      hostVersion: "0.20.0",
      rank: "excellent",
    });
    const code = readFileSync(path.join(result.moduleDir, "src/index.ts"), "utf-8");
    expect(code).toContain('rank: "excellent"');
  });

  it("rejects invalid module ids", () => {
    expect(() =>
      createModule({
        id: "NotLower",
        template: "offense",
        targetDir: tmp,
        hostVersion: "0.20.0",
      }),
    ).toThrow(/Invalid module id/);
  });

  it("refuses to overwrite without --force", () => {
    createModule({
      id: "my-mod",
      template: "offense",
      targetDir: tmp,
      hostVersion: "0.20.0",
    });
    expect(() =>
      createModule({
        id: "my-mod",
        template: "offense",
        targetDir: tmp,
        hostVersion: "0.20.0",
      }),
    ).toThrow(/already exists/);
  });

  it("overwrites when --force is set", () => {
    const first = createModule({
      id: "my-mod",
      template: "offense",
      targetDir: tmp,
      hostVersion: "0.20.0",
    });
    const marker = path.join(first.moduleDir, "marker.txt");
    writeFileSync(marker, "sentinel", "utf-8");
    const second = createModule({
      id: "my-mod",
      template: "offense",
      targetDir: tmp,
      hostVersion: "0.20.0",
      force: true,
    });
    expect(second.moduleDir).toBe(first.moduleDir);
    // Overwrite replaces the scaffolded files; the marker survives because
    // the scaffolder writes individual files rather than wiping the dir.
    expect(existsSync(marker)).toBe(true);
  });

  it("rejects invalid ranks", () => {
    expect(isValidRank("excellent")).toBe(true);
    expect(isValidRank("legendary")).toBe(false);
  });

  it("rejects invalid templates", () => {
    expect(isValidTemplate("offense")).toBe(true);
    expect(isValidTemplate("social")).toBe(false);
  });
});

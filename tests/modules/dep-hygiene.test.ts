/**
 * Unit tests for the dep-hygiene module (v0.21 followup N5).
 *
 * Each manifest analyser is a pure function over a (filePath, raw) pair —
 * the fixtures under `tests/fixtures/dep-hygiene/{node,python,rust,go}/`
 * exercise the realistic shapes operators have in their repos.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  analyzeManifest,
  createDepHygieneModule,
} from "../../src/modules/dep-hygiene/dep-hygiene.js";

const FIXTURES = path.join(__dirname, "..", "fixtures", "dep-hygiene");

function loadFixture(subdir: string, manifestName: string): { filePath: string; raw: string } {
  const filePath = path.join(FIXTURES, subdir, manifestName);
  return { filePath, raw: readFileSync(filePath, "utf8") };
}

describe("dep-hygiene module shape", () => {
  it("registers `dep-hygiene:check` as the only tool", () => {
    const mod = createDepHygieneModule();
    expect(mod.id).toBe("dep-hygiene");
    expect(mod.tools.map((t) => t.name)).toEqual(["dep-hygiene:check"]);
    expect(mod.category).toBe("defense");
  });
});

describe("analyzeManifest('package.json')", () => {
  it("flags @latest, *, and floor-only ranges; passes a clean pin", () => {
    const { filePath, raw } = loadFixture("node", "package.json");
    const findings = analyzeManifest("package.json", filePath, raw);
    const byPackage = new Map(findings.map((f) => [f.packageName, f]));

    expect(byPackage.get("lodash")?.severity).toBe("high");
    expect(byPackage.get("express")?.severity).toBe("high");
    expect(byPackage.get("axios")?.severity).toBe("medium");
    expect(byPackage.get("left-pad")?.severity).toBe("low");
    expect(byPackage.get("vitest")?.severity).toBe("high");

    expect(byPackage.has("good-lib")).toBe(false);
    expect(byPackage.has("react")).toBe(false);
  });

  it("returns an empty list for an unparseable manifest", () => {
    const findings = analyzeManifest("package.json", "/tmp/bad", "{ this is not json");
    expect(findings).toEqual([]);
  });
});

describe("analyzeManifest('pyproject.toml')", () => {
  it("flags PEP 508 unconstrained / floor-only and Poetry wildcard / floor-only", () => {
    const { filePath, raw } = loadFixture("python", "pyproject.toml");
    const findings = analyzeManifest("pyproject.toml", filePath, raw);
    const byPackage = new Map(findings.map((f) => [f.packageName, f]));

    expect(byPackage.get("requests")?.severity).toBe("medium");
    expect(byPackage.get("flask")?.severity).toBe("high");
    expect(byPackage.has("django")).toBe(false);
    expect(byPackage.has("pydantic")).toBe(false);

    expect(byPackage.get("loguru")?.severity).toBe("high");
    expect(byPackage.get("httpx")?.severity).toBe("medium");
    expect(byPackage.has("sqlalchemy")).toBe(false);
    expect(byPackage.has("python")).toBe(false);
  });
});

describe("analyzeManifest('Cargo.toml')", () => {
  it("flags wildcard and floor-only requirements", () => {
    const { filePath, raw } = loadFixture("rust", "Cargo.toml");
    const findings = analyzeManifest("Cargo.toml", filePath, raw);
    const byPackage = new Map(findings.map((f) => [f.packageName, f]));

    expect(byPackage.get("serde")?.severity).toBe("high");
    expect(byPackage.get("tokio")?.severity).toBe("medium");
    expect(byPackage.has("anyhow")).toBe(false);
    expect(byPackage.has("proptest")).toBe(false);
  });
});

describe("analyzeManifest('go.mod')", () => {
  it("flags pseudo-version commit pins and `latest` / v0.0.0", () => {
    const { filePath, raw } = loadFixture("go", "go.mod");
    const findings = analyzeManifest("go.mod", filePath, raw);
    const byPackage = new Map(findings.map((f) => [f.packageName, f]));

    expect(byPackage.has("github.com/example/safe")).toBe(false);
    expect(byPackage.get("github.com/example/commit-pin")?.severity).toBe("medium");
    expect(byPackage.get("github.com/example/floating")?.severity).toBe("high");
    expect(byPackage.get("github.com/example/zero")?.severity).toBe("high");
  });
});

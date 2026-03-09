import { describe, it, expect } from "vitest";
import { getParameterRisk, extractParameterRisk } from "../src/parameter-risk.js";

describe("getParameterRisk", () => {
  it("identifies SQLi-prone parameters", () => {
    const risk = getParameterRisk("id");
    expect(risk).toBeDefined();
    expect(risk!.categories).toContain("SQLi-prone");
    expect(risk!.boost).toBe(0.15);
  });

  it("identifies SSRF-prone parameters", () => {
    const risk = getParameterRisk("url");
    expect(risk).toBeDefined();
    expect(risk!.categories).toContain("SSRF-prone");
    expect(risk!.boost).toBe(0.15);
  });

  it("identifies path traversal-prone parameters", () => {
    const risk = getParameterRisk("file");
    expect(risk).toBeDefined();
    expect(risk!.categories).toContain("Path traversal-prone");
    expect(risk!.boost).toBe(0.15);
  });

  it("identifies auth-sensitive parameters", () => {
    const risk = getParameterRisk("password");
    expect(risk).toBeDefined();
    expect(risk!.categories).toContain("Auth-sensitive");
    expect(risk!.boost).toBe(0.10);
  });

  it("is case-insensitive", () => {
    const risk = getParameterRisk("URL");
    expect(risk).toBeDefined();
    expect(risk!.categories).toContain("SSRF-prone");
  });

  it("returns undefined for unknown parameters", () => {
    expect(getParameterRisk("fooBarBaz123")).toBeUndefined();
  });

  it("handles user_id which is both SQLi and Auth", () => {
    const risk = getParameterRisk("user_id");
    expect(risk).toBeDefined();
    expect(risk!.categories.length).toBeGreaterThanOrEqual(1);
  });
});

describe("extractParameterRisk", () => {
  it("extracts parameter names from finding messages", () => {
    const risk = extractParameterRisk("SQL injection via parameter: id in user query");
    expect(risk).toBeDefined();
    expect(risk!.categories).toContain("SQLi-prone");
  });

  it("extracts from req.query.url pattern", () => {
    const risk = extractParameterRisk('SSRF via req.query.url used in fetch call');
    expect(risk).toBeDefined();
    expect(risk!.categories).toContain("SSRF-prone");
  });

  it("extracts from req.body[\"file\"] pattern", () => {
    const risk = extractParameterRisk('Path traversal via req.body["file"]');
    expect(risk).toBeDefined();
    expect(risk!.categories).toContain("Path traversal-prone");
  });

  it("returns undefined when no high-risk parameters found", () => {
    const risk = extractParameterRisk("Generic security issue with no param names");
    expect(risk).toBeUndefined();
  });

  it("picks highest boost when multiple params found", () => {
    // "id" has 0.15 boost, "password" has 0.10
    const risk = extractParameterRisk("Check password and id parameters for injection");
    expect(risk).toBeDefined();
    expect(risk!.boost).toBe(0.15);
  });
});

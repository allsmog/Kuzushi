import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { formatPreflightCheck, runPreflight, whichSync } from "../../src/cli/preflight.js";
import type { KuzushiConfig } from "../../src/types.js";

function baseConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 5,
    triageConcurrency: 2,
    scanMode: "parallel",
    tasks: [],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
    ...overrides,
  } as KuzushiConfig;
}

describe("whichSync", () => {
  it("locates a core binary that definitely exists (node)", () => {
    expect(whichSync("node")).not.toBeNull();
  });

  it("returns null for a non-existent binary", () => {
    expect(whichSync("definitely-not-a-real-binary-xyz-123")).toBeNull();
  });
});

describe("runPreflight", () => {
  let tmp: string;
  let prevKey: string | undefined;
  let prevAuthToken: string | undefined;
  let prevOauthToken: string | undefined;

  beforeEach(() => {
    tmp = mkdtempSync(path.join(tmpdir(), "kuzushi-preflight-"));
    prevKey = process.env.ANTHROPIC_API_KEY;
    prevAuthToken = process.env.ANTHROPIC_AUTH_TOKEN;
    prevOauthToken = process.env.ANTHROPIC_OAUTH_TOKEN;
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
    if (prevKey === undefined) {
      delete process.env.ANTHROPIC_API_KEY;
    } else {
      process.env.ANTHROPIC_API_KEY = prevKey;
    }
    if (prevAuthToken === undefined) {
      delete process.env.ANTHROPIC_AUTH_TOKEN;
    } else {
      process.env.ANTHROPIC_AUTH_TOKEN = prevAuthToken;
    }
    if (prevOauthToken === undefined) {
      delete process.env.ANTHROPIC_OAUTH_TOKEN;
    } else {
      process.env.ANTHROPIC_OAUTH_TOKEN = prevOauthToken;
    }
  });

  it("flags missing ANTHROPIC_API_KEY as an error for the default backend", () => {
    delete process.env.ANTHROPIC_API_KEY;
    const report = runPreflight(baseConfig(), tmp);
    const credCheck = report.checks.find((c) => c.name === "credentials");
    expect(credCheck?.status).toBe("missing");
    expect(report.issues.some((i) => i.path === "credentials" && i.severity === "error")).toBe(
      true,
    );
  });

  it("reports credentials ok when ANTHROPIC_API_KEY is set", () => {
    process.env.ANTHROPIC_API_KEY = `sk-ant-test-${"x".repeat(40)}`;
    const report = runPreflight(baseConfig(), tmp);
    const credCheck = report.checks.find((c) => c.name === "credentials");
    expect(credCheck?.status).toBe("ok");
    expect(report.issues.some((i) => i.path === "credentials")).toBe(false);
  });

  it("reports credentials ok when ANTHROPIC_AUTH_TOKEN is set", () => {
    delete process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_AUTH_TOKEN = "sk-ant-oat-test";
    const report = runPreflight(baseConfig(), tmp);
    const credCheck = report.checks.find((c) => c.name === "credentials");
    expect(credCheck?.status).toBe("ok");
    expect(report.issues.some((i) => i.path === "credentials")).toBe(false);
  });

  it("reports credentials ok when ANTHROPIC_OAUTH_TOKEN is set", () => {
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_AUTH_TOKEN;
    process.env.ANTHROPIC_OAUTH_TOKEN = "sk-ant-oat-test";
    const report = runPreflight(baseConfig(), tmp);
    const credCheck = report.checks.find((c) => c.name === "credentials");
    expect(credCheck?.status).toBe("ok");
    expect(report.issues.some((i) => i.path === "credentials")).toBe(false);
  });

  it("only errors on missing scanner binaries when the task is enabled", () => {
    delete process.env.ANTHROPIC_API_KEY;
    const withoutSemgrep = runPreflight(baseConfig({ tasks: [] }), tmp);
    const withSemgrep = runPreflight(baseConfig({ tasks: ["semgrep"] }), tmp);

    // Whether semgrep is installed locally varies — we only assert the
    // difference: the enabled config produces an error if the binary is
    // missing; the disabled config never does.
    const unenabledSemgrep = withoutSemgrep.issues.find((i) => i.path === "tasks.semgrep");
    expect(unenabledSemgrep).toBeUndefined();

    const semgrepBin = whichSync("semgrep");
    if (!semgrepBin) {
      expect(withSemgrep.issues.some((i) => i.path === "tasks.semgrep")).toBe(true);
    }
  });

  it("passes the data-dir check when the repo root is writable", () => {
    const report = runPreflight(baseConfig(), tmp);
    const dataCheck = report.checks.find((c) => c.name === "data-dir");
    expect(dataCheck?.status).toBe("ok");
  });
});

describe("formatPreflightCheck", () => {
  it("renders each status with a distinguishable prefix", () => {
    expect(formatPreflightCheck({ name: "x", status: "ok" })).toMatch(/^\[ok\]/);
    expect(formatPreflightCheck({ name: "x", status: "missing" })).toMatch(/^\[MISSING\]/);
    expect(formatPreflightCheck({ name: "x", status: "skipped" })).toMatch(/^\[skipped\]/);
  });
});

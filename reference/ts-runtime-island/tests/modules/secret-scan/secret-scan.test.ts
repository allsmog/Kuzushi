import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_DETECTORS,
  redactSecret,
  shannonEntropy,
} from "../../../src/modules/secret-scan/detectors.js";
import { detectSecretsInText, scanForSecrets } from "../../../src/modules/secret-scan/scan.js";
import { createSecretScanModule } from "../../../src/modules/secret-scan/secret-scan.js";
import { createMockToolContext } from "../../../src/testing/index.js";

const FIX_ROOT = path.join(__dirname, "../../fixtures/secret-scan");

describe("secret-scan detectors", () => {
  it("shannon entropy distinguishes high- and low-entropy strings", () => {
    expect(shannonEntropy("aaaaaaaa")).toBe(0);
    expect(shannonEntropy("0000000000000000")).toBe(0);
    expect(shannonEntropy("ZxQ9-aB3cV8nM2pK")).toBeGreaterThan(3.5);
    expect(shannonEntropy("")).toBe(0);
  });

  it("redactSecret keeps a 4-char prefix and pads the rest", () => {
    expect(redactSecret("ghp_ABCDEFGHIJKL")).toMatch(/^ghp_\*+$/);
    expect(redactSecret("xy")).toBe("***");
  });

  it("detects AWS access keys without an entropy gate", () => {
    const text = `aws_access_key_id = AKIAIOSFODNN7EXAMPLE`;
    const hits = detectSecretsInText(text, DEFAULT_DETECTORS);
    expect(hits.some((h) => h.detector.id === "aws-access-key")).toBe(true);
  });

  it("detects GitHub PATs and Slack tokens", () => {
    // Vendor-shaped prefixes are concatenated at test time so this file
    // doesn't trip third-party secret-scanning blocklists on push.
    const ghp = `${"ghp"}_ABCdefGHIjklMNOpqrSTUvwxYZ0123456789`;
    const xoxb = `${"xox"}b-1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUv`;
    const text = [`GITHUB_TOKEN=${ghp}`, `SLACK_BOT_TOKEN=${xoxb}`].join("\n");
    const ids = new Set(detectSecretsInText(text, DEFAULT_DETECTORS).map((h) => h.detector.id));
    expect(ids.has("github-pat")).toBe(true);
    expect(ids.has("slack-token")).toBe(true);
  });

  it("entropy gate drops low-entropy placeholder credentials", () => {
    const text = `password = "changeme00000000"`;
    const hits = detectSecretsInText(text, DEFAULT_DETECTORS);
    const generic = hits.filter((h) => h.detector.id === "generic-secret-assignment");
    expect(generic).toHaveLength(0);
  });

  it("detects PEM private key blocks", () => {
    const text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK0Q\n-----END RSA PRIVATE KEY-----";
    const hits = detectSecretsInText(text, DEFAULT_DETECTORS);
    expect(hits.some((h) => h.detector.id === "pem-private-key")).toBe(true);
  });
});

describe("scanForSecrets (filesystem)", () => {
  it("finds zero secrets in the clean fixture", async () => {
    const result = await scanForSecrets(path.join(FIX_ROOT, "clean"));
    expect(result.findings).toHaveLength(0);
    expect(result.filesScanned).toBeGreaterThan(0);
  });

  it("finds the planted secrets in the leaks fixture and skips node_modules", async () => {
    const result = await scanForSecrets(path.join(FIX_ROOT, "leaks"));
    expect(result.findings.length).toBeGreaterThan(0);
    const ruleIds = new Set(result.findings.map((f) => f.ruleId));
    expect(ruleIds.has("secret-scan/aws-access-key")).toBe(true);
    expect(ruleIds.has("secret-scan/github-pat")).toBe(true);
    expect(ruleIds.has("secret-scan/pem-private-key")).toBe(true);
    // node_modules/ must be excluded by default — even though it contains
    // the same AWS key shape.
    const filePaths = result.findings.map((f) => f.filePath);
    expect(filePaths.every((p) => !p.startsWith("node_modules/"))).toBe(true);
  });

  it("emits stable secret-scan: fingerprints", async () => {
    const a = await scanForSecrets(path.join(FIX_ROOT, "leaks"));
    const b = await scanForSecrets(path.join(FIX_ROOT, "leaks"));
    const fps = a.findings.map((f) => f.fingerprint).sort();
    const fps2 = b.findings.map((f) => f.fingerprint).sort();
    expect(fps).toEqual(fps2);
    expect(fps.every((fp) => fp.startsWith("secret-scan:"))).toBe(true);
  });

  it("evidence redacts the matched secret instead of leaking it", async () => {
    const result = await scanForSecrets(path.join(FIX_ROOT, "leaks"));
    const aws = result.findings.find((f) => f.ruleId === "secret-scan/aws-access-key");
    expect(aws).toBeDefined();
    expect(aws?.evidence).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(aws?.evidence).toContain("***");
  });

  it("respects maxFindings to bound runtime", async () => {
    const result = await scanForSecrets(path.join(FIX_ROOT, "leaks"), { maxFindings: 1 });
    expect(result.findings).toHaveLength(1);
  });

  it("rejects non-directory targets with a descriptive error", async () => {
    await expect(scanForSecrets(path.join(FIX_ROOT, "leaks", "aws.txt"))).rejects.toThrow(
      /not a directory/,
    );
  });
});

describe("createSecretScanModule", () => {
  it("exposes secret-scan:scan on the secret-scan module", () => {
    const mod = createSecretScanModule();
    expect(mod.id).toBe("secret-scan");
    expect(mod.category).toBe("defense");
    const names = mod.tools.map((t) => t.name);
    expect(names).toEqual(["secret-scan:scan"]);
    expect(mod.tools[0]?.headless).toBe(true);
  });

  it("scan tool returns findings + summary on the leaks fixture", async () => {
    const mod = createSecretScanModule();
    const tool = mod.tools.find((t) => t.name === "secret-scan:scan")!;
    const ctx = createMockToolContext({
      cwd: path.join(FIX_ROOT, "leaks"),
      target: path.join(FIX_ROOT, "leaks"),
    });
    const result = await tool.execute({}, ctx);
    expect(result.ok).toBe(true);
    expect(result.output).toMatch(/secret-scan: \d+ finding/);
    const data = result.data as {
      findings: { ruleId: string }[];
      filesScanned: number;
    };
    expect(data.findings.length).toBeGreaterThan(0);
    expect(data.filesScanned).toBeGreaterThan(0);
  });

  it("scan tool returns ok=true with zero findings on a clean tree", async () => {
    const mod = createSecretScanModule();
    const tool = mod.tools.find((t) => t.name === "secret-scan:scan")!;
    const ctx = createMockToolContext({
      cwd: path.join(FIX_ROOT, "clean"),
      target: path.join(FIX_ROOT, "clean"),
    });
    const result = await tool.execute({}, ctx);
    expect(result.ok).toBe(true);
    expect(result.output).toContain("0 finding");
    expect(result.output).toContain("no secrets detected");
  });

  it("scan tool propagates filesystem errors as ok=false", async () => {
    const mod = createSecretScanModule();
    const tool = mod.tools.find((t) => t.name === "secret-scan:scan")!;
    const ctx = createMockToolContext({
      cwd: "/nonexistent/path/that/does/not/exist",
      target: "/nonexistent/path/that/does/not/exist",
    });
    const result = await tool.execute({}, ctx);
    expect(result.ok).toBe(false);
    expect(result.output).toContain("secret-scan error");
  });

  it("severity filter narrows results to the requested levels", async () => {
    const mod = createSecretScanModule();
    const tool = mod.tools.find((t) => t.name === "secret-scan:scan")!;
    const ctx = createMockToolContext({
      cwd: path.join(FIX_ROOT, "leaks"),
      target: path.join(FIX_ROOT, "leaks"),
    });
    const result = await tool.execute({ severity: ["ERROR"] }, ctx);
    expect(result.ok).toBe(true);
    const data = result.data as { findings: { severity: string }[] };
    expect(data.findings.every((f) => f.severity === "ERROR")).toBe(true);
  });
});

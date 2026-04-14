import { describe, expect, it } from "vitest";
import {
  buildCryptoBehavioralSystemPrompt,
  buildEdgeCaseHarnessPrompt,
  buildEcbModeHarnessPrompt,
  buildKeyLengthHarnessPrompt,
  buildTimingHarnessPrompt,
  buildWeakHashHarnessPrompt,
  buildWeakPrngHarnessPrompt,
  resolveCryptoHarnessLanguage,
} from "../../src/crypto-behavioral/harness-prompts.js";
import type { Finding } from "../../src/scanners/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    taskId: "crypto-misuse-detect",
    fingerprint: "fp-1",
    ruleId: "crypto-misuse/timing-attack",
    filePath: "src/auth.ts",
    startLine: 42,
    severity: "WARNING",
    message: "Potential timing leak",
    evidence: "Uses === for HMAC comparison",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-208"],
    score: 75,
    ...overrides,
  };
}

describe("crypto behavioral harness prompts", () => {
  it("builds the shared system prompt with anti-hallucination and output contract guidance", () => {
    const prompt = buildCryptoBehavioralSystemPrompt({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      authPatterns: [],
      sanitizationLibs: [],
      ormOrDb: [],
      entryPoints: [],
    });

    expect(prompt).toContain("Anti-hallucination constraints");
    expect(prompt).toContain("CRYPTO_RESULT:");
    expect(prompt).toContain("fingerprint, test_type, script_content");
    expect(prompt).toContain("Languages: TypeScript");
  });

  it("builds per-test prompts with the correct behavioral instructions", () => {
    expect(buildTimingHarnessPrompt(makeFinding(), "/tmp/repo")).toContain("Welch's t-test");
    expect(buildTimingHarnessPrompt(makeFinding(), "/tmp/repo")).toContain("process.hrtime.bigint()");

    expect(buildEcbModeHarnessPrompt(
      makeFinding({ ruleId: "crypto-misuse/ecb-mode" }),
      "/tmp/repo",
    )).toContain("identical 16-byte blocks");

    expect(buildWeakHashHarnessPrompt(
      makeFinding({ ruleId: "crypto-misuse/hash-for-auth" }),
      "/tmp/repo",
    )).toContain("MD5, SHA1");

    expect(buildWeakPrngHarnessPrompt(
      makeFinding({ ruleId: "crypto-misuse/insecure-prng" }),
      "/tmp/repo",
    )).toContain("Math.random");

    expect(buildKeyLengthHarnessPrompt(
      makeFinding({ ruleId: "crypto-misuse/key-length" }),
      "/tmp/repo",
    )).toContain("key size in bits");

    expect(buildEdgeCaseHarnessPrompt(
      makeFinding({ ruleId: "crypto-misuse/tls-config" }),
      "/tmp/repo",
    )).toContain("self-signed certs");
  });

  it("selects supported runtime languages and avoids TypeScript output", () => {
    expect(resolveCryptoHarnessLanguage(
      makeFinding({ filePath: "src/service.ts" }),
      {
        languages: ["TypeScript"],
        frameworks: [],
        authPatterns: [],
        sanitizationLibs: [],
        ormOrDb: [],
        entryPoints: [],
      },
    )).toBe("javascript");

    expect(resolveCryptoHarnessLanguage(
      makeFinding({ filePath: "service.py" }),
      {
        languages: ["Python"],
        frameworks: [],
        authPatterns: [],
        sanitizationLibs: [],
        ormOrDb: [],
        entryPoints: [],
      },
    )).toBe("python");

    expect(resolveCryptoHarnessLanguage(
      makeFinding({ filePath: "main.go" }),
      {
        languages: ["Go"],
        frameworks: [],
        authPatterns: [],
        sanitizationLibs: [],
        ormOrDb: [],
        entryPoints: [],
      },
    )).toBe("go");
  });
});

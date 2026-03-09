import { describe, expect, it } from "vitest";
import type { AgentMessage, AgentQueryRequest, AgentRuntime } from "../src/agent-runtime/types.js";
import type { Finding } from "../src/scanners/types.js";
import type { TriageResult } from "../src/types.js";
import {
  buildVerificationPrompt,
  parseVerificationOutput,
  VERIFICATION_RESULT_SCHEMA,
  VerificationExecutionError,
  verifyFindingWithAgent,
} from "../src/verify.js";

function makeFinding(): Finding {
  return {
    scanner: "semgrep",
    fingerprint: "verify-fp",
    ruleId: "test.rule",
    filePath: "src/app.ts",
    startLine: 10,
    severity: "ERROR",
    message: "Possible SQL injection",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-89"],
    score: 88,
  };
}

function makeTriageResult(verdict: TriageResult["verdict"] = "tp"): TriageResult {
  return {
    fingerprint: "verify-fp",
    verdict,
    confidence: 0.93,
    rationale: "User input appears attacker-controlled at sink.",
    verificationSteps: ["Trace source to sink", "Check sanitization"],
    fixPatch: null,
  };
}

function stream(messages: AgentMessage[]): AsyncIterable<AgentMessage> {
  return (async function* () {
    for (const message of messages) {
      yield message;
    }
  })();
}

function makeRuntime(
  messages: AgentMessage[],
  requests: AgentQueryRequest[],
): AgentRuntime {
  return {
    id: "test-runtime",
    query(request) {
      requests.push(request);
      return stream(messages);
    },
  };
}

describe("buildVerificationPrompt", () => {
  it("includes finding details and triage context", () => {
    const prompt = buildVerificationPrompt(makeFinding(), makeTriageResult(), "repo");

    expect(prompt).toContain("exploit engineer");
    expect(prompt).toContain("Repo: repo");
    expect(prompt).toContain("Rule: test.rule");
    expect(prompt).toContain("Fingerprint: verify-fp");
    expect(prompt).toContain("Verdict: tp");
    expect(prompt).toContain("User input appears attacker-controlled");
  });

  it("includes repository context when provided", () => {
    const prompt = buildVerificationPrompt(
      makeFinding(),
      makeTriageResult(),
      "repo",
      {
        languages: ["TypeScript"],
        frameworks: ["Express"],
        authPatterns: ["JWT"],
        sanitizationLibs: ["helmet"],
        ormOrDb: ["Prisma"],
        entryPoints: ["src/pages/api/*"],
      },
    );

    expect(prompt).toContain("## Repository Context");
    expect(prompt).toContain("Languages: TypeScript");
    expect(prompt).toContain("ORM/DB: Prisma");
  });

  it("includes Proof Level Framework and Bypass Exhaustion Protocol", () => {
    const prompt = buildVerificationPrompt(makeFinding(), makeTriageResult(), "repo");

    expect(prompt).toContain("Proof Level Framework");
    expect(prompt).toContain("Level 1: Theoretical weakness identified");
    expect(prompt).toContain("Level 4: Account takeover demonstrated");
    expect(prompt).toContain("Bypass Exhaustion Protocol");
    expect(prompt).toContain("Direct exploitation with obvious payload");
    expect(prompt).toContain("Encoding bypass");
  });

  it("includes bypass techniques for SQLi CWE", () => {
    const prompt = buildVerificationPrompt(makeFinding(), makeTriageResult(), "repo");

    expect(prompt).toContain("Category-Specific Bypass Techniques");
    expect(prompt).toContain("SQL Injection");
    expect(prompt).toContain("Comment injection");
    expect(prompt).toContain("Wide-byte injection");
  });

  it("includes Confidence Escalation Protocol for verification", () => {
    const prompt = buildVerificationPrompt(makeFinding(), makeTriageResult(), "repo");

    expect(prompt).toContain("Confidence Escalation Protocol");
    expect(prompt).toContain("Start at 0.1");
  });
});

describe("parseVerificationOutput", () => {
  it("parses structured object output", () => {
    const parsed = parseVerificationOutput({
      fingerprint: "verify-fp",
      exploitable: true,
      poc_payload: "' OR 1=1 --",
      poc_description: "Inject payload into login form.",
      attack_vector: "HTTP body",
      preconditions: ["Attacker can reach login endpoint"],
      confidence: 0.87,
    }, "fallback");

    expect(parsed.fingerprint).toBe("verify-fp");
    expect(parsed.exploitable).toBe(true);
    expect(parsed.pocPayload).toBe("' OR 1=1 --");
    expect(parsed.attackVector).toBe("HTTP body");
    expect(parsed.preconditions).toEqual(["Attacker can reach login endpoint"]);
    expect(parsed.confidence).toBe(0.87);
  });

  it("parses string output and clamps confidence", () => {
    const parsed = parseVerificationOutput(
      JSON.stringify({
        exploitable: false,
        poc_payload: null,
        poc_description: "Input is sanitized before sink.",
        attack_vector: null,
        preconditions: [],
        confidence: 3,
      }),
      "fallback-fp",
    );

    expect(parsed.fingerprint).toBe("fallback-fp");
    expect(parsed.exploitable).toBe(false);
    expect(parsed.pocPayload).toBeNull();
    expect(parsed.confidence).toBe(1);
  });

  it("throws a clear error for malformed JSON", () => {
    expect(() => parseVerificationOutput("not-json", "fallback-fp"))
      .toThrow("Invalid verification JSON response");
  });

  it("parses proof_level and proof_verdict from output", () => {
    const parsed = parseVerificationOutput({
      fingerprint: "verify-fp",
      exploitable: true,
      poc_payload: "payload",
      poc_description: "desc",
      attack_vector: "network",
      preconditions: [],
      confidence: 0.9,
      proof_level: 3,
      proof_verdict: "exploited",
      bypass_attempts: ["Direct injection", "Encoding bypass"],
    }, "fallback");

    expect(parsed.proofLevel).toBe(3);
    expect(parsed.proofVerdict).toBe("exploited");
    expect(parsed.bypassAttempts).toEqual(["Direct injection", "Encoding bypass"]);
  });

  it("handles missing proof fields gracefully", () => {
    const parsed = parseVerificationOutput({
      fingerprint: "verify-fp",
      exploitable: false,
      poc_payload: null,
      poc_description: "not exploitable",
      attack_vector: null,
      preconditions: [],
      confidence: 0.3,
    }, "fallback");

    expect(parsed.proofLevel).toBeUndefined();
    expect(parsed.proofVerdict).toBeUndefined();
    expect(parsed.bypassAttempts).toBeUndefined();
  });

  it("normalizes invalid proof_verdict to undefined", () => {
    const parsed = parseVerificationOutput({
      fingerprint: "verify-fp",
      exploitable: false,
      poc_payload: null,
      poc_description: "desc",
      attack_vector: null,
      preconditions: [],
      confidence: 0.5,
      proof_level: 5,
      proof_verdict: "invalid_verdict",
    }, "fallback");

    expect(parsed.proofLevel).toBeUndefined(); // 5 is out of range
    expect(parsed.proofVerdict).toBeUndefined();
  });
});

describe("verifyFindingWithAgent", () => {
  it("captures total cost and passes schema/tools to runtime", async () => {
    const requests: AgentQueryRequest[] = [];
    const runtime = makeRuntime(
      [{
        type: "result",
        subtype: "success",
        result: "{}",
        structuredOutput: {
          fingerprint: "verify-fp",
          exploitable: true,
          poc_payload: "' OR 1=1 --",
          poc_description: "Inject payload in username",
          attack_vector: "Form input",
          preconditions: ["Reachable endpoint"],
          confidence: 0.9,
        },
        totalCostUsd: 0.0142,
      }],
      requests,
    );

    const output = await verifyFindingWithAgent(
      makeFinding(),
      makeTriageResult(),
      "/tmp/repo",
      "repo",
      "claude-haiku-4-5-20251001",
      12,
      { runtime },
    );

    expect(output.result.exploitable).toBe(true);
    expect(output.costUsd).toBe(0.0142);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.options?.allowedTools).toEqual(["Read", "Glob", "Grep"]);
    expect(requests[0]?.options?.outputFormat?.schema).toBe(VERIFICATION_RESULT_SCHEMA);
    expect(requests[0]?.options?.maxTurns).toBe(12);
  });

  it("throws VerificationExecutionError with cost on parse failure", async () => {
    const requests: AgentQueryRequest[] = [];
    const runtime = makeRuntime(
      [{
        type: "result",
        subtype: "success",
        result: "not-json",
        totalCostUsd: 0.009,
      }],
      requests,
    );

    try {
      await verifyFindingWithAgent(
        makeFinding(),
        makeTriageResult(),
        "/tmp/repo",
        "repo",
        "claude-haiku-4-5-20251001",
        12,
        { runtime },
      );
      expect.unreachable("Expected verification to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(VerificationExecutionError);
      expect((error as VerificationExecutionError).costUsd).toBe(0.009);
      expect((error as Error).message).toContain("verification output parse failed");
    }
  });
});

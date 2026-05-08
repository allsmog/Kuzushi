import { describe, expect, it } from "vitest";
import { generateMarkdownReport } from "../src/report-markdown.js";
import type { Finding } from "../src/scanners/types.js";
import {
  createRun,
  initDb,
  updateRunStatus,
  updateVerificationResult,
  upsertFinding,
} from "../src/store.js";
import type { KuzushiConfig, ScanOpts, TriageResult, VerificationResult } from "../src/types.js";

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: { semgrep: {} },
  };
}

function makeScanOpts(): ScanOpts {
  return {
    severity: ["ERROR"],
    excludePatterns: [],
    tasks: ["semgrep"],
    fresh: false,
  };
}

function makeFinding(): Finding {
  return {
    taskId: "semgrep",
    fingerprint: "fp-md-1",
    ruleId: "test.rule",
    filePath: "src/app.ts",
    startLine: 8,
    severity: "ERROR",
    message: "Potential SQL injection",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-89"],
    score: 88,
  };
}

function makeTriageResult(): TriageResult {
  return {
    fingerprint: "fp-md-1",
    verdict: "tp",
    confidence: 0.94,
    rationale: "User-controlled input reaches SQL sink.",
    verificationSteps: ["trace source", "verify sink"],
    fixPatch: null,
  };
}

function makeVerificationResult(): VerificationResult {
  return {
    fingerprint: "fp-md-1",
    exploitable: true,
    pocPayload: "' OR 1=1 --",
    pocDescription: "Inject in query param",
    attackVector: "HTTP query",
    preconditions: ["Endpoint reachable"],
    confidence: 0.89,
  };
}

describe("generateMarkdownReport", () => {
  it("scopes report to fingerprints when provided", () => {
    const db = initDb(":memory:");
    const runId = "run-md-fp";

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, runId, "triaging");

    const finding1 = { ...makeFinding(), fingerprint: "fp-current" };
    const triage1 = { ...makeTriageResult(), fingerprint: "fp-current" };
    upsertFinding(db, finding1, triage1, "repo", "HEAD");

    const finding2 = { ...makeFinding(), fingerprint: "fp-stale", ruleId: "stale.rule" };
    const triage2 = { ...makeTriageResult(), fingerprint: "fp-stale" };
    upsertFinding(db, finding2, triage2, "repo", "HEAD");

    const markdown = generateMarkdownReport(
      db,
      "repo",
      { totalFindings: 1, queuedForTriage: 1, skippedAlreadyTriaged: 0 },
      runId,
      ["fp-current"],
    );

    expect(markdown).toContain("test.rule");
    expect(markdown).not.toContain("stale.rule");

    db.close();
  });

  it("renders summary and actionable findings sections", () => {
    const db = initDb(":memory:");
    const runId = "run-md-1";

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, runId, "triaging");

    const finding = makeFinding();
    const triage = makeTriageResult();
    upsertFinding(db, finding, triage, "repo", "HEAD");

    const verification = makeVerificationResult();
    updateVerificationResult(db, finding.fingerprint, verification);

    const markdown = generateMarkdownReport(
      db,
      "repo",
      {
        totalFindings: 1,
        queuedForTriage: 1,
        skippedAlreadyTriaged: 0,
        skippedLowConfidence: 0,
        triaged: 1,
        triageErrors: 2,
        verified: 1,
        verifyErrors: 1,
        startedAt: "2026-01-01T00:00:00.000Z",
        completedAt: "2026-01-01T00:01:00.000Z",
      },
      runId,
    );

    expect(markdown).toContain("# Kuzushi Security Report - repo");
    expect(markdown).toContain("## Summary");
    expect(markdown).toContain("## Actionable Findings");
    expect(markdown).toContain("Verification result: **EXPLOITABLE**");
    expect(markdown).toContain("| Triage errors | 2 |");
    expect(markdown).toContain("| Verification errors | 1 |");
    expect(markdown).toContain("```text");
    expect(markdown).toContain("' OR 1=1 --");

    db.close();
  });

  it("renders codex-cyber-style per-finding sections (title, summary, validation, artifact, attack path)", () => {
    const db = initDb(":memory:");
    const runId = "run-md-codex";

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, runId, "triaging");

    const finding = { ...makeFinding(), fingerprint: "fp-codex" };
    const triage: TriageResult = {
      fingerprint: "fp-codex",
      verdict: "tp",
      confidence: 0.92,
      rationale: "Raw rationale — used only when no attack narrative exists.",
      verificationSteps: [
        "Identify shell default allowed tools (src/copilot/shell.ts:28).",
        "Verify allowedTools passes into agent session (src/agent-runtime/claude.ts:433-454).",
      ],
      fixPatch: null,
      title: "Copilot shell enables Bash tool for LLM command execution",
      displaySeverity: "high",
      attackNarrative:
        "Alice, controlling repo content, triggers prompt injection; Bob runs kuzushi shell and the LLM invokes Bash, granting Alice RCE on Bob's host.",
      codeCitations: [
        {
          filePath: "src/copilot/shell.ts",
          startLine: 28,
          endLine: 28,
          snippet: 'const SHELL_ALLOWED_TOOLS = ["Read", "Glob", "Grep", "Bash", "LS"];',
          description: "Shell whitelists Bash by default",
        },
      ],
      attackPath: {
        chain: [
          "Untrusted repo content",
          "Prompt injection into LLM session",
          "Bash tool dispatch",
          "bash -c executes on host",
        ],
        narrative: "Repo content flows into LLM, which invokes Bash.",
        likelihoodReasoning: "Medium — requires running the shell with LLM credentials.",
        impactReasoning: "High — arbitrary code execution on operator host.",
      },
      assumptions: ["Operator runs the interactive copilot shell with LLM credentials."],
      controls: [
        {
          name: "Tool policy framework",
          description: "Supports allow/deny layers, but Bash is allowed by default.",
          filePath: "src/prompts/tool-policy.ts",
        },
      ],
      blindspots: ["No dynamic PoC executed."],
    };
    upsertFinding(db, finding, triage, "repo", "HEAD");

    const markdown = generateMarkdownReport(db, "repo", {}, runId);

    // Title used as heading, not ruleId
    expect(markdown).toContain("### Copilot shell enables Bash tool for LLM command execution");
    // Display severity surfaced, uppercased
    expect(markdown).toContain("- Severity: **HIGH**");
    // Summary uses attack narrative, not raw rationale
    expect(markdown).toContain("**Summary.**");
    expect(markdown).toContain("Alice, controlling repo content");
    // Validation steps present and numbered
    expect(markdown).toContain("**Validation.**");
    expect(markdown).toContain("1. Identify shell default allowed tools");
    expect(markdown).toContain("2. Verify allowedTools passes into agent session");
    // Evidence block renamed to "Validation artifact"
    expect(markdown).toContain("**Validation artifact.**");
    expect(markdown).toContain("SHELL_ALLOWED_TOOLS");
    // Attack-path chain rendered with arrows
    expect(markdown).toContain("**Attack-path analysis.**");
    expect(markdown).toContain("Untrusted repo content --> Prompt injection into LLM session");
    // Likelihood and impact are first-class labels
    expect(markdown).toContain("**Likelihood.** Medium");
    expect(markdown).toContain("**Impact.** High");

    db.close();
  });

  it("escapes triple-backtick sequences in PoC payload to prevent fence injection", () => {
    const db = initDb(":memory:");
    const runId = "run-md-fence";

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, runId, "triaging");

    const finding = makeFinding();
    finding.fingerprint = "fp-md-fence";
    const triage = makeTriageResult();
    triage.fingerprint = "fp-md-fence";
    upsertFinding(db, finding, triage, "repo", "HEAD");
    // Write a PoC payload that contains triple backticks
    updateVerificationResult(db, "fp-md-fence", {
      fingerprint: "fp-md-fence",
      exploitable: true,
      pocPayload: "payload here\n```\n# Injected Heading\n```\nmore payload",
      pocDescription: "desc",
      attackVector: "HTTP",
      preconditions: [],
      confidence: 0.9,
    });

    const markdown = generateMarkdownReport(db, "repo", {}, runId);

    // The raw triple-backtick should be escaped (not appear as literal ```)
    // and should NOT produce an injected heading
    expect(markdown).not.toContain("# Injected Heading\n```\nmore");
    // The escaped content should still contain the zero-width-space separated backticks
    expect(markdown).toContain("payload here");
    expect(markdown).toContain("more payload");

    db.close();
  });
});

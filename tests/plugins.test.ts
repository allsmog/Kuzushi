import { describe, expect, it } from "vitest";
import { SemgrepPlugin } from "../src/scanners/semgrep.js";
import { ClaudeAdkPlugin } from "../src/scanners/claude-adk.js";
import type { Finding } from "../src/scanners/types.js";

function makeFinding(scanner: string): Finding {
  return {
    scanner,
    fingerprint: "fp",
    ruleId: "rule",
    filePath: "src/app.ts",
    startLine: 10,
    severity: "ERROR",
    message: "msg",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-79"],
    score: 54,
  };
}

describe("scanner plugin triage prompts", () => {
  it("SemgrepPlugin prompt references pattern semantics", () => {
    const plugin = new SemgrepPlugin();
    const config = plugin.triageAgentConfig(makeFinding("semgrep"), "repo");
    expect(config.prompt).toContain("Semgrep");
    expect(config.prompt.toLowerCase()).toContain("pattern");
  });

  it("ClaudeAdkPlugin prompt references prior agentic analysis", () => {
    const plugin = new ClaudeAdkPlugin();
    const config = plugin.triageAgentConfig(makeFinding("claude-adk"), "repo");
    expect(config.prompt.toLowerCase()).toContain("prior agentic scan pass");
    expect(config.prompt.toLowerCase()).toContain("correct or mistaken");
  });
});

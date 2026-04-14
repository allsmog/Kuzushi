import { describe, expect, it } from "vitest";
import { SemgrepPlugin } from "../src/scanners/semgrep.js";
import { AgenticPlugin } from "../src/scanners/agentic.js";
import { CodeQLPlugin } from "../src/scanners/codeql.js";
import type { Finding } from "../src/scanners/types.js";

function makeFinding(taskId: string): Finding {
  return {
    taskId,
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

  it("AgenticPlugin prompt references prior agentic analysis", () => {
    const plugin = new AgenticPlugin();
    const config = plugin.triageAgentConfig(makeFinding("agentic"), "repo");
    expect(config.prompt.toLowerCase()).toContain("prior agentic scan pass");
    expect(config.prompt.toLowerCase()).toContain("correct or mistaken");
  });

  it("CodeQLPlugin prompt references semantic dataflow analysis", () => {
    const plugin = new CodeQLPlugin();
    const config = plugin.triageAgentConfig(makeFinding("codeql"), "repo");
    expect(config.prompt.toLowerCase()).toContain("dataflow/taint");
    expect(config.prompt.toLowerCase()).toContain("source-to-sink");
  });
});

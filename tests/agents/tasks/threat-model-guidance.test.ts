import { describe, expect, it } from "vitest";
import type { PreReadResult } from "../../../src/agents/tasks/pre-read.js";
import {
  __threatModelGuidanceInternals,
  buildThreatModelLeadsSection,
} from "../../../src/agents/tasks/threat-model-guidance.js";
import type { FileIndex } from "../../../src/types.js";

function makeStrideOutput(threats: Array<Record<string, unknown>>): unknown {
  return {
    document: {
      version: "1.0",
      dfd: {
        elements: [],
        trustBoundaries: [],
      },
      threats,
      summary: {
        total: threats.length,
        bySeverity: {},
        byCategory: {
          spoofing: 0,
          tampering: 0,
          repudiation: 0,
          "information-disclosure": threats.length,
          "denial-of-service": 0,
          "elevation-of-privilege": 0,
        },
      },
    },
    findings: [],
  };
}

function makeFileIndex(paths: string[]): FileIndex {
  return {
    tree: paths.map((entry) => ({ path: entry })),
    totalFiles: paths.length,
    truncated: false,
    patternMatches: {
      "eval-exec": [
        {
          pattern: "fetch",
          filePath: "src/http/proxy.ts",
          lineNumber: 14,
          lineContent: "return fetch(targetUrl);",
        },
      ],
    },
  };
}

function makePreRead(paths: Array<{ path: string; content: string }>): PreReadResult {
  return {
    files: paths,
    totalBytes: paths.reduce((sum, item) => sum + item.content.length, 0),
    truncated: false,
  };
}

describe("buildThreatModelLeadsSection", () => {
  it("renders a compact STRIDE leads section when upstream output exists", () => {
    const output = buildThreatModelLeadsSection(
      "ssrf-detect",
      makeStrideOutput([
        {
          id: "threat-1",
          elementId: "elem-1",
          category: "information-disclosure",
          title: "User-controlled URL can reach internal metadata",
          description: "A proxy endpoint fetches attacker-provided URLs without an allowlist.",
          attackVector: "Attacker supplies targetUrl to fetch()",
          preconditions: [],
          impact: "high",
          likelihood: "high",
          existingMitigations: [],
          missingMitigations: ["allowlist"],
          relatedCwe: ["CWE-918"],
          affectedFiles: [{ filePath: "src/http/proxy.ts", startLine: 14 }],
          evidenceAnchors: [
            { filePath: "src/http/proxy.ts", startLine: 14, description: "fetch(targetUrl)" },
          ],
        },
      ]),
      makeFileIndex(["src/http/proxy.ts"]),
      makePreRead([{ path: "src/http/proxy.ts", content: "return fetch(targetUrl);" }]),
    );

    expect(output).toContain("## Threat model leads from STRIDE");
    expect(output).toContain("[threat-1] information-disclosure / high / CWE-918");
    expect(output).toContain("Why relevant: file overlap, CWE-918, keyword match, high impact");
    expect(output).toContain("Evidence: src/http/proxy.ts:14 (fetch(targetUrl))");
  });

  it("prefers file overlap over a loose keyword-only match", () => {
    const fileIndex = makeFileIndex(["src/http/proxy.ts", "src/other.ts"]);
    const preRead = makePreRead([
      { path: "src/http/proxy.ts", content: "return fetch(targetUrl);" },
    ]);
    const scoreWithOverlap = __threatModelGuidanceInternals.scoreThreatForTask(
      "ssrf-detect",
      {
        id: "threat-a",
        elementId: "elem-1",
        category: "information-disclosure",
        title: "Internal admin trust issue",
        description: "Admin proxy forwards privileged traffic.",
        attackVector: "User controls upstream route",
        preconditions: [],
        impact: "medium",
        likelihood: "medium",
        existingMitigations: [],
        missingMitigations: [],
        relatedCwe: [],
        affectedFiles: [{ filePath: "src/http/proxy.ts", startLine: 14 }],
        evidenceAnchors: [],
      },
      __threatModelGuidanceInternals.collectShortlistPaths("ssrf-detect", fileIndex, preRead),
      __threatModelGuidanceInternals.buildShortlistCorpus(
        "ssrf-detect",
        fileIndex,
        preRead,
        __threatModelGuidanceInternals.collectShortlistPaths("ssrf-detect", fileIndex, preRead),
      ),
    );
    const keywordOnlyScore = __threatModelGuidanceInternals.scoreThreatForTask(
      "ssrf-detect",
      {
        id: "threat-b",
        elementId: "elem-1",
        category: "information-disclosure",
        title: "Redirect fetch metadata exposure",
        description: "A redirect can reach metadata services.",
        attackVector: "User controls URL redirects",
        preconditions: [],
        impact: "high",
        likelihood: "medium",
        existingMitigations: [],
        missingMitigations: [],
        relatedCwe: [],
        affectedFiles: [{ filePath: "src/unrelated/controller.ts", startLine: 22 }],
        evidenceAnchors: [],
      },
      __threatModelGuidanceInternals.collectShortlistPaths("ssrf-detect", fileIndex, preRead),
      __threatModelGuidanceInternals.buildShortlistCorpus(
        "ssrf-detect",
        fileIndex,
        preRead,
        __threatModelGuidanceInternals.collectShortlistPaths("ssrf-detect", fileIndex, preRead),
      ),
    );

    expect(scoreWithOverlap.score).toBeGreaterThan(keywordOnlyScore.score);
  });

  it("omits the section when no valid STRIDE output exists", () => {
    expect(buildThreatModelLeadsSection("ssrf-detect", undefined, undefined, undefined)).toBe("");
    expect(buildThreatModelLeadsSection("ssrf-detect", { nope: true }, undefined, undefined)).toBe(
      "",
    );
  });
});

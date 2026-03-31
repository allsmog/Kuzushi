// This file contains DETECTION PATTERNS for a security scanner.
// The patterns match dangerous coding practices in scanned repositories.
// These are intentionally matching insecure code — that is the purpose of SAST.

import type { Finding } from "../../scanners/types.js";
import type { RepoContext } from "../../types.js";
import { createLogger } from "../../logger.js";
import { toErrorMessage } from "../../utils.js";
import type { AnalysisStrategy, StrategyInput, StrategyResult, StrategyEvidence } from "../types.js";

const log = createLogger({ stage: "strategy-syntactic" });

const SUPPORTED_CWES = new Set([
  "CWE-89", "CWE-79", "CWE-78", "CWE-94", "CWE-95", "CWE-22", "CWE-502",
  "CWE-943", "CWE-1336", "CWE-1321", "CWE-798", "CWE-327", "CWE-326", "CWE-829",
  "CWE-611", "CWE-776",
]);

/** Detection patterns keyed by CWE — used to find vulnerable code in target repos. */
const CWE_PATTERNS: Record<string, Array<{ pattern: string; description: string }>> = {
  "CWE-89": [
    { pattern: "query\\s*\\(.*\\+|query\\s*\\(.*\\$\\{", description: "String concatenation in SQL query" },
    { pattern: "raw\\s*\\(.*\\+|rawQuery", description: "Raw SQL with concatenation" },
  ],
  "CWE-79": [
    { pattern: "innerHTML\\s*=|v-html", description: "Direct HTML insertion" },
    { pattern: "document\\.write", description: "DOM write with potential user input" },
  ],
  "CWE-78": [
    { pattern: "spawn\\s*\\(.*\\+|system\\s*\\(", description: "Command execution with concatenation" },
  ],
  "CWE-94": [
    { pattern: "Function\\s*\\(|setTimeout\\s*\\(.*,", description: "Dynamic code evaluation" },
  ],
  "CWE-22": [
    { pattern: "path\\.join\\s*\\(.*req\\.|readFile.*req\\.", description: "File access with user input" },
  ],
  "CWE-502": [
    { pattern: "yaml\\.load\\s*\\(|unserialize\\s*\\(", description: "Unsafe deserialization call" },
  ],
  "CWE-943": [
    { pattern: "\\$where|\\$regex|\\$ne|\\$gt|\\$lt", description: "MongoDB operator in query" },
    { pattern: "find\\s*\\(.*req\\.|findOne\\s*\\(.*req\\.", description: "Direct user input in NoSQL query" },
  ],
  "CWE-1336": [
    { pattern: "render_template_string|Template\\s*\\(.*req\\.", description: "User input in template construction" },
    { pattern: "new\\s+Function\\s*\\(|compile\\s*\\(.*req\\.", description: "Dynamic template compilation with user input" },
  ],
  "CWE-1321": [
    { pattern: "__proto__|constructor\\s*\\[|Object\\.assign\\s*\\(.*req\\.", description: "Prototype pollution vector" },
    { pattern: "merge\\s*\\(.*req\\.|extend\\s*\\(.*req\\.", description: "Deep merge with user input" },
  ],
  "CWE-798": [
    { pattern: "password\\s*=\\s*[\"']|api_key\\s*=\\s*[\"']|secret\\s*=\\s*[\"']", description: "Hardcoded credential" },
  ],
  "CWE-327": [
    { pattern: "createHash\\s*\\([\"']md5|createHash\\s*\\([\"']sha1", description: "Weak hash algorithm" },
    { pattern: "DES|RC4|ECB", description: "Weak cipher or mode" },
  ],
  "CWE-829": [
    { pattern: "postinstall|preinstall", description: "Install script in package.json" },
    { pattern: "eval\\s*\\(.*require|import\\s*\\(.*http", description: "Dynamic remote import" },
  ],
  "CWE-611": [
    { pattern: "DocumentBuilderFactory|SAXParserFactory|XMLInputFactory", description: "Java XML parser (check entity config)" },
    { pattern: "lxml\\.etree|xml\\.sax|minidom", description: "Python XML parser (check entity defaults)" },
    { pattern: "LIBXML_NOENT|loadXML|simplexml_load", description: "PHP XML with entity processing" },
    { pattern: "XmlDocument|XmlTextReader", description: ".NET XML parser (check XmlResolver)" },
  ],
};

export function createSyntacticStrategy(strategyId: string, cweIds: string[]): AnalysisStrategy {
  return {
    id: strategyId,
    kind: "syntactic",
    displayName: `Syntactic Pattern Matching (${cweIds.join(", ")})`,
    costTier: 1,

    appliesTo(targetCweIds: string[]): boolean {
      return targetCweIds.some((cwe) => SUPPORTED_CWES.has(cwe));
    },

    async run(input: StrategyInput): Promise<StrategyResult> {
      const startTime = Date.now();
      const findings: Finding[] = [];
      const evidence: StrategyEvidence[] = [];

      const patterns: Array<{ pattern: string; description: string; cwe: string }> = [];
      for (const cwe of cweIds) {
        for (const p of CWE_PATTERNS[cwe] ?? []) {
          patterns.push({ ...p, cwe });
        }
      }

      // Use KnowledgeModule detection keywords if available
      const knowledgeRegistry = input.context.knowledgeRegistry;
      if (knowledgeRegistry) {
        for (const mod of knowledgeRegistry.query({ cwes: cweIds })) {
          for (const keyword of mod.detectionKeywords) {
            patterns.push({
              pattern: keyword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
              description: `Knowledge: ${keyword}`,
              cwe: mod.cwes[0] ?? cweIds[0]!,
            });
          }
        }
      }

      if (patterns.length === 0) {
        return {
          strategyKind: "syntactic", strategyId,
          findings: [], confidence: 0, costUsd: 0,
          durationMs: Date.now() - startTime, evidence: [],
        };
      }

      const runtime = input.context.runtime;
      const cwd = input.context.scanPath ?? input.context.repoRoot;

      for (const { pattern, description } of patterns) {
        try {
          for await (const message of runtime.query({
            prompt: `Search the codebase for the regex pattern: ${pattern}\nUse the Grep tool. Return file paths and line numbers.`,
            options: {
              cwd,
              model: "anthropic:claude-haiku-4-5",
              allowedTools: ["Grep", "Glob"],
              permissionMode: "dontAsk",
            },
          })) {
            if (message.type === "result" && "result" in message && message.result) {
              evidence.push({
                kind: "pattern-match",
                description: `${description}: pattern found in codebase`,
              });
            }
          }
        } catch (error) {
          log.debug(`Pattern search failed for '${pattern}': ${toErrorMessage(error)}`);
        }
      }

      const confidence = evidence.length > 0 ? Math.min(0.7, 0.3 + evidence.length * 0.1) : 0;

      return {
        strategyKind: "syntactic", strategyId, findings, confidence,
        costUsd: 0, durationMs: Date.now() - startTime, evidence,
      };
    },
  };
}

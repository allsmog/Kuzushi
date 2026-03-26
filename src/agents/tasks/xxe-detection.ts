import { createHash } from "node:crypto";
import path from "node:path";
import {
  antiHallucinationModule,
  frameworkAwarenessModule,
} from "../../prompts/modules.js";
import { coerceRepoContext, coerceFileIndex } from "../../repo-context.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { FileIndex, RepoContext, ScanOpts } from "../../types.js";
import { isRecord } from "../../utils.js";
import { createLogger } from "../../logger.js";
import type { AgentTask, TaskContext } from "../types.js";
import { preReadFilesForTask, type PreReadResult } from "./pre-read.js";
import { formatFileTreeForPrompt, formatPreReadForPrompt } from "./pre-read-prompt.js";
import { resolveTaskModel, resolveTaskPositiveInt, resolveTaskRuntime, resolveTaskAllowedTools } from "./runtime-overrides.js";
import { buildApplicationModelSection, buildThreatScenarioEvidenceSection } from "./scenario-guidance.js";
import type { ApplicationModel } from "../../types.js";

const log = createLogger({ stage: "xxe-detection" });

const XXE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["findings"],
  properties: {
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["category", "filePath", "startLine", "severity", "description", "cwe", "confidence", "rationale"],
        properties: {
          category: { type: "string", enum: ["xxe-parse", "xxe-config", "ssrf-via-dtd", "billion-laughs"] },
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          description: { type: "string" },
          cwe: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
          parserApi: { type: "string" },
          inputSource: { type: "string" },
        },
      },
    },
  },
} as const;

interface XxeFinding {
  category: string;
  filePath: string;
  startLine: number;
  severity: string;
  description: string;
  cwe: string;
  confidence: string;
  rationale: string;
  parserApi?: string;
  inputSource?: string;
}

function buildPrompt(repoContext: RepoContext | undefined, maxFindings: number, fileIndex?: FileIndex, preRead?: PreReadResult, appModelContext?: string, scenarioContext?: string): string {
  const contextLines = repoContext
    ? [
        "## Repository context",
        `- Languages: ${repoContext.languages.join(", ") || "unknown"}`,
        `- Frameworks: ${repoContext.frameworks.join(", ") || "unknown"}`,
        "",
      ]
    : [];

  return [
    "You are a senior application security engineer specializing in XML External Entity (XXE) injection (CWE-611).",
    "Your task: identify XML parsers that process untrusted input with external entity processing enabled.",
    "",
    ...contextLines,
    ...(appModelContext ? [appModelContext, ""] : []),
    ...(scenarioContext ? [scenarioContext, ""] : []),
    "## Categories to detect",
    "",
    "### xxe-parse (CWE-611)",
    "XML parsers processing untrusted input without disabling external entities.",
    "Java: DocumentBuilderFactory, SAXParserFactory, XMLInputFactory without FEATURE_SECURE_PROCESSING,",
    "  DISALLOW_DOCTYPE_DECL, or EXTERNAL_GENERAL_ENTITIES = false.",
    "Python: xml.etree.ElementTree (safe by default), lxml.etree (vulnerable by default),",
    "  xml.sax (vulnerable), xml.dom.minidom (vulnerable). defusedxml is SAFE.",
    "Node.js: xml2js (safe by default), fast-xml-parser (check processEntities option),",
    "  libxmljs (check noent option), node-expat (safe).",
    "PHP: simplexml_load_string with LIBXML_NOENT, DOMDocument::loadXML without disabling entities.",
    ".NET: XmlDocument, XmlTextReader without XmlResolver = null.",
    "",
    "### xxe-config (CWE-611)",
    "XML parser configuration that explicitly ENABLES dangerous features.",
    "Factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', false),",
    "parser.setProperty with external entities enabled, LIBXML_NOENT flag usage.",
    "",
    "### ssrf-via-dtd (CWE-918)",
    "XML parsers that can be used for SSRF via DTD fetching.",
    "Even without general entity expansion, DTD fetching to attacker-controlled URLs",
    "allows port scanning and internal service discovery.",
    "",
    "### billion-laughs (CWE-776)",
    "XML parsers vulnerable to entity expansion DoS (billion laughs / XML bomb).",
    "Parsers without entity expansion limits processing untrusted XML.",
    "",
    formatFileTreeForPrompt(fileIndex, false),
    formatPreReadForPrompt(preRead ?? { files: [], totalBytes: 0, truncated: false }),
    "## Investigation methodology",
    ...(preRead && preRead.files.length > 0
      ? [
          "1. Analyze pre-loaded files for XML parser usage.",
          "2. Use Grep to find additional XML parsing calls.",
        ]
      : [
          "1. Use Grep to find XML parsers: DocumentBuilderFactory, SAXParser, XMLInputFactory,",
          "   etree.parse, lxml, xml2js, fast-xml-parser, DOMDocument, XmlDocument.",
          "2. Read parser configuration to check if external entities are disabled.",
        ]),
    "3. Trace where the XML input comes from — is it user-controlled (HTTP body, file upload, API)?",
    "4. Check if defusedxml (Python) or equivalent safe wrapper is used.",
    "5. Verify parser feature flags: DISALLOW_DOCTYPE_DECL, EXTERNAL_GENERAL_ENTITIES, noent, processEntities.",
    "",
    antiHallucinationModule({
      extra: [
        "defusedxml in Python is SAFE — do NOT flag it.",
        "xml2js in Node.js is safe by default — only flag if explicitXMLEntities is enabled.",
        "Do NOT flag XML parsing of hardcoded/internal-only XML.",
        "Do NOT flag parsers that have external entities explicitly disabled.",
      ],
    }),
    frameworkAwarenessModule(repoContext),
    "",
    `Return at most ${maxFindings} findings, prioritized by severity and confidence.`,
    "Filter out any finding where your confidence would be below MEDIUM.",
  ].filter(Boolean).join("\n");
}

function normalizeFindings(raw: unknown, repoRoot: string, repoName: string, maxFindings: number): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["findings"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["findings"] as unknown[]) {
    if (!isRecord(item)) continue;
    const f = item as unknown as XxeFinding;
    if (!f.filePath?.trim()) continue;

    const filePath = path.isAbsolute(f.filePath) ? (path.relative(repoRoot, f.filePath) || f.filePath) : f.filePath;
    const cweList = f.cwe ? [f.cwe] : ["CWE-611"];
    const source = [repoName, "xxe", f.category, filePath, String(f.startLine)].join("|");
    const fingerprint = createHash("sha256").update(source).digest("hex");

    const finding: Finding = {
      scanner: "xxe-detect",
      fingerprint,
      ruleId: `xxe/${f.category || "unknown"}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(f.startLine) || 1)),
      severity: f.severity || "ERROR",
      message: `${f.description || "Potential XXE vulnerability"}${f.parserApi ? ` [${f.parserApi}]` : ""}`,
      evidence: f.rationale || null,
      scannerConfidence: f.confidence || "HIGH",
      subcategory: ["vuln"],
      likelihood: f.confidence || "HIGH",
      impact: "HIGH",
      cwe: cweList,
      score: scoreFindingMetadata({
        severity: f.severity || "ERROR",
        likelihood: f.confidence || "HIGH",
        impact: "HIGH",
        subcategory: ["vuln"],
        cwe: cweList,
      }),
    };

    const existing = deduped.get(fingerprint);
    if (!existing || finding.score > existing.score) {
      deduped.set(fingerprint, finding);
    }
  }

  return [...deduped.values()].sort((a, b) => b.score - a.score).slice(0, maxFindings);
}

export const xxeDetectionTask: AgentTask<ScanOpts, Finding[]> = {
  id: "xxe-detect",
  displayName: "XXE Detection",
  outputKind: "findings",
  dependsOn: ["context-gatherer", "app-model-build", "threat-scenario-build"],

  async run(_input, context): Promise<Finding[]> {
    const model = resolveTaskModel(context, "xxe-detect");
    const maxFindings = resolveTaskPositiveInt(context, "xxe-detect", "maxFindings", 50);
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const fileIndex = coerceFileIndex(context.upstreamOutputs.get("context-gatherer"));
    const preRead = await preReadFilesForTask("xxe-detect", fileIndex, context.repoRoot);
    const applicationModel = context.upstreamOutputs.get("app-model-build") as ApplicationModel | undefined;
    const scenarioOutput = context.upstreamOutputs.get("threat-scenario-build");
    const appModelContext = buildApplicationModelSection("xxe-detect", applicationModel);
    const scenarioContext = await buildThreatScenarioEvidenceSection("xxe-detect", context.repoRoot, applicationModel, scenarioOutput);

    const runtime = resolveTaskRuntime(context);
    const prompt = buildPrompt(repoContext, maxFindings, fileIndex, preRead, appModelContext, scenarioContext);
    let structuredOutput: unknown;
    let costUsd = 0;

    for await (const message of runtime.query({
      prompt,
      options: {
        cwd: context.repoRoot,
        model,
        maxTurns: Math.min(context.config.taskMaxTurns ?? 15, 10),
        allowedTools: resolveTaskAllowedTools(context),
        permissionMode: "dontAsk",
        outputFormat: {
          type: "json_schema",
          schema: XXE_SCHEMA,
          strict: true,
          retryInvalidStructuredOutput: 1,
        },
      },
    })) {
      if (message.type !== "result") continue;
      if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) costUsd = message.totalCostUsd;
      if ("result" in message) structuredOutput = message.structuredOutput;
    }

    const findings = normalizeFindings(structuredOutput, context.repoRoot, context.repoName, maxFindings);
    log.info(`Found ${findings.length} XXE findings (cost=$${costUsd.toFixed(4)})`);
    return attachTaskOutputMeta(findings, { costUsd });
  },

  triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig {
    return {
      prompt: [
        `You are triaging an XXE finding in "${repoName}".`,
        `Rule: ${finding.ruleId}`,
        `File: ${finding.filePath}:${finding.startLine}`,
        `Message: ${finding.message}`,
        finding.evidence ? `Rationale: ${finding.evidence}` : "",
        "",
        "Verify:",
        "1. The XML parser exists at the reported location.",
        "2. External entity processing is NOT disabled in the parser configuration.",
        "3. The XML input is user-controlled (HTTP body, file upload, API input).",
        "4. No safe wrapper (defusedxml, etc.) is used.",
      ].filter(Boolean).join("\n"),
    };
  },
};

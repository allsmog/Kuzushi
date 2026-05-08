import { extractJsonObject, isRecord } from "../../utils.js";
import type {
  VendorAssessmentCompletenessGate,
  VendorAssessmentProfile,
  VendorAssessmentReportJson,
  VendorAssessmentScope,
} from "./types.js";

export function assessCompleteness(
  scope: VendorAssessmentScope,
  profile: VendorAssessmentProfile,
): VendorAssessmentCompletenessGate {
  const allText = scope.documents
    .map((doc) => doc.extracted?.text ?? "")
    .join("\n")
    .toLowerCase();
  const detectedIntegrations = detectCriticalIntegrations(scope, profile);
  const useCase =
    scope.useCase || /\b(use case|business purpose|workflow|user story)\b/.test(allText)
      ? "yes"
      : scope.documents.length > 0
        ? "partial"
        : "no";
  const integrations =
    scope.integrations.length > 0 || detectedIntegrations.length > 0
      ? "yes"
      : /\b(integration|oauth|saml|api key|webhook|connector)\b/.test(allText)
        ? "partial"
        : "no";
  const architectureDiagram = scope.documents.some((doc) => doc.kind === "diagram")
    ? "yes"
    : /\b(data flow diagram|architecture diagram|dfd|trust boundary)\b/.test(allText)
      ? "partial"
      : "no";
  const missingArtifacts: string[] = [];
  if (useCase !== "yes") missingArtifacts.push("use case statement");
  if (integrations !== "yes") missingArtifacts.push("integration and data-flow inventory");
  if (architectureDiagram !== "yes") missingArtifacts.push("architecture or data-flow diagram");
  if (!scope.documents.some((doc) => doc.kind === "questionnaire")) {
    missingArtifacts.push("security questionnaire");
  }
  const missingCore = [useCase, integrations, architectureDiagram].filter((v) => v !== "yes");
  return {
    useCase,
    integrations,
    architectureDiagram,
    missingArtifacts,
    failed: missingCore.length >= 2,
  };
}

export function detectCriticalIntegrations(
  scope: VendorAssessmentScope,
  profile: VendorAssessmentProfile,
): string[] {
  const haystack = [
    scope.integrations.join("\n"),
    scope.documents.map((doc) => `${doc.title}\n${doc.extracted?.text ?? ""}`).join("\n"),
  ]
    .join("\n")
    .toLowerCase();
  return profile.criticalIntegrations.filter((name) => haystack.includes(name.toLowerCase()));
}

export function hasMeaningfulDocumentText(scope: VendorAssessmentScope): boolean {
  return scope.documents.some((doc) => (doc.extracted?.charCount ?? 0) >= 100);
}

export function buildFallbackReport(input: {
  runId: string;
  scope: VendorAssessmentScope;
  profile: VendorAssessmentProfile;
  mode: "document-backed" | "intake";
  artifacts: VendorAssessmentReportJson["artifacts"];
}): { markdown: string; json: VendorAssessmentReportJson } {
  const generatedAt = new Date().toISOString();
  const gate = assessCompleteness(input.scope, input.profile);
  const criticalIntegrations = detectCriticalIntegrations(input.scope, input.profile);
  const hasCriticalIntegration = criticalIntegrations.length > 0;
  const hasMissingEvidence = gate.failed || gate.missingArtifacts.length > 0;
  const overallRisk: VendorAssessmentReportJson["overallRisk"] =
    hasCriticalIntegration && gate.failed
      ? "Critical"
      : hasCriticalIntegration || hasMissingEvidence
        ? "High"
        : "Medium";
  const questions = baselineQuestions(input.scope, input.profile, gate);
  const weaknesses: VendorAssessmentReportJson["weaknesses"] = gate.missingArtifacts.map(
    (artifact, index) => ({
      id: `W0.${index + 1}`,
      severity: (gate.failed ? "High" : "Medium") as "High" | "Medium",
      confidence: "High" as const,
      summary: `Missing assessment artifact: ${artifact}.`,
    }),
  );
  if (input.scope.integrations.length > 0) {
    weaknesses.push({
      id: "W1.1",
      severity: hasCriticalIntegration ? "High" : "Medium",
      confidence: input.mode === "document-backed" ? "Medium" : "Low",
      summary: `Integration security evidence is incomplete for ${input.scope.integrations.join(
        ", ",
      )}: credential storage, token rotation, exact scopes or permissions, revocation, and deletion propagation were not established by the attached evidence.`,
    });
  }
  const mitigations = [
    `[Addresses: Completeness Gate] Do not approve production use until the missing artifacts are supplied and reviewed: ${gate.missingArtifacts.join(", ") || "none"}.`,
    "[Addresses: Baseline] Require least-privilege integration scopes, documented credential storage, rotation, and auditable administrative access before production use.",
    "[Addresses: Evidence Limits] Treat public or metadata-only evidence as follow-up material, not as a substitute for private control reports, contractual terms, architecture diagrams, or security questionnaires.",
  ];
  const json: VendorAssessmentReportJson = {
    runId: input.runId,
    generatedAt,
    profile: input.profile.id,
    mode: input.mode,
    confidence: input.mode === "intake" ? "intake" : "document-backed",
    vendor: {
      name: input.scope.vendorName,
      product: input.scope.productName,
      domain: input.scope.primaryDomain,
    },
    overallRisk,
    criticalIntegrations,
    completenessGate: gate,
    documents: input.scope.documents.map((doc) => ({
      id: doc.id,
      title: doc.title,
      kind: doc.kind,
      status: doc.status,
      source: doc.source,
      warnings: doc.parseWarnings,
    })),
    weaknesses,
    mitigations,
    questions,
    artifacts: input.artifacts,
    validation: {
      appendixParsed: false,
      warnings: ["Generated fallback report because model output was unavailable or malformed."],
    },
  };
  return { markdown: renderReportMarkdown(json, input.scope), json };
}

export function parseReportJsonAppendix(
  markdown: string,
): Partial<VendorAssessmentReportJson> | undefined {
  const appendix = markdown.match(/Appendix:[\s\S]*?```(?:json)?\s*([\s\S]*?)```/i);
  if (!appendix) return undefined;
  try {
    const parsed = JSON.parse(extractJsonObject(appendix[1] ?? ""));
    return isRecord(parsed) ? normalizeAppendix(parsed) : undefined;
  } catch {
    return undefined;
  }
}

export function mergeReportJson(input: {
  base: VendorAssessmentReportJson;
  markdown: string;
}): VendorAssessmentReportJson {
  const appendix = parseReportJsonAppendix(input.markdown);
  if (!appendix) return input.base;
  return {
    ...input.base,
    ...appendix,
    runId: input.base.runId,
    generatedAt: input.base.generatedAt,
    profile: input.base.profile,
    mode: input.base.mode,
    confidence: input.base.confidence,
    vendor: input.base.vendor,
    documents: input.base.documents,
    artifacts: input.base.artifacts,
    validation: {
      appendixParsed: true,
      warnings: input.base.validation.warnings,
    },
  };
}

function baselineQuestions(
  scope: VendorAssessmentScope,
  profile: VendorAssessmentProfile,
  gate: VendorAssessmentCompletenessGate,
): string[] {
  const questions = [...profile.rubric.baselineQuestions];
  if (!scope.vendorName)
    questions.unshift("Identify the vendor, product name, and primary security contact.");
  if (gate.missingArtifacts.length > 0) {
    questions.unshift(`Provide the missing artifacts: ${gate.missingArtifacts.join(", ")}.`);
  }
  return questions;
}

function renderReportMarkdown(
  json: VendorAssessmentReportJson,
  scope: VendorAssessmentScope,
): string {
  const vendor = json.vendor.name ?? "Unknown Vendor";
  const docRows =
    json.documents.length > 0
      ? json.documents
          .map(
            (doc) =>
              `| ${tableCell(doc.title)} | ${doc.kind} | ${doc.status} | ${tableCell(doc.warnings.join("; ") || "none")} |`,
          )
          .join("\n")
      : "| No documents attached | other | metadata-only | intake packet only |";
  const integrationRows =
    scope.integrations.length > 0
      ? scope.integrations
          .map((name) => {
            const evidence = findEvidenceLine(scope, [
              new RegExp(`\\b${escapeRegExp(name)}\\b`, "i"),
            ]);
            const authEvidence = findEvidenceLine(scope, [
              new RegExp(
                `\\b${escapeRegExp(name)}\\b.*\\b(oauth|api key|api credentials?|credentials?|token|saml|sso)\\b`,
                "i",
              ),
              new RegExp(
                `\\b(oauth|api key|api credentials?|credentials?|token|saml|sso)\\b.*\\b${escapeRegExp(name)}\\b`,
                "i",
              ),
            ]);
            return `| ${tableCell(name)} | ${evidence ? "Documented" : "Explicit"} | Unknown | ${tableCell(summarizeAuthEvidence(authEvidence))} | ${tableCell(evidence ?? "Declared in scope; no supporting sentence found in parsed documents")} |`;
          })
          .join("\n")
      : "| Not provided | Inferred | Unknown | Not disclosed | No integration inventory was attached |";
  const exceptionText =
    json.criticalIntegrations.length > 0
      ? json.criticalIntegrations
          .map((name) => {
            const evidence = findEvidenceLine(scope, [
              new RegExp(`\\b${escapeRegExp(name)}\\b`, "i"),
            ]);
            return `- Exception: Critical integration review trigger for ${name}\n  Evidence: ${evidence ?? "Mentioned in attached scope or documents."}\n  Business Impact: High-sensitivity enterprise data path requires manual architecture and credential review.`;
          })
          .join("\n")
      : json.completenessGate.failed
        ? '- Exception: Document completeness gate failed\n  Vendor Reference: "Required artifacts were not supplied."\n  Business Impact: The assessment lacks enough evidence to approve the integration.'
        : "No critical exceptions identified.";
  const evidenceHighlights = collectEvidenceHighlights(scope);
  const evidenceHighlightText =
    evidenceHighlights.length > 0
      ? evidenceHighlights.map((line) => `- ${line}`).join("\n")
      : "- No parsed evidence highlights were available.";
  const limitations = collectEvidenceLimitations(json, scope);
  const limitationText = limitations.map((line) => `- ${line}`).join("\n");
  const referenceLinks = collectReferenceLinks(scope);
  const referenceText =
    referenceLinks.length > 0
      ? referenceLinks.map((url) => `- ${url}`).join("\n")
      : "- No source URLs were present in the attached evidence.";
  const validationWarning =
    json.validation.warnings.length > 0
      ? json.validation.warnings.map((warning) => `- ${warning}`).join("\n")
      : "- None.";
  return [
    "# Vendor AI Security Assessment Report",
    "",
    "## Document Metadata",
    "",
    `Date: ${json.generatedAt.slice(0, 10)}`,
    `Vendor Assessed: ${vendor}`,
    `Vendor Domain: ${json.vendor.domain ?? "Not disclosed"}`,
    `Assessment Type: Vendor AI Security, Identity & Privacy Review`,
    `Overall Risk Rating: ${json.overallRisk}`,
    `Confidence: ${json.confidence}`,
    "",
    "## Section 0.5 Document Completeness & Integration Inventory",
    "",
    "Document Completeness Gate:",
    "",
    "| Required artifact | Present? | Evidence |",
    "|---|---|---|",
    `| Clearly stated use case | ${titleCase(json.completenessGate.useCase)} | ${scope.useCase ?? "Not present in scope"} |`,
    `| Enumerated list of integrations with data flows | ${titleCase(json.completenessGate.integrations)} | ${scope.integrations.join(", ") || "Not present in scope"} |`,
    `| Architecture / data flow diagram | ${titleCase(json.completenessGate.architectureDiagram)} | ${scope.documents.some((doc) => doc.kind === "diagram") ? "Attached diagram document" : "Not present in scope"} |`,
    "",
    json.completenessGate.failed
      ? "Document completeness gate FAILED. The risk rating is raised because required artifacts are missing."
      : "Document completeness gate did not hard-fail, but human review is still required.",
    "",
    "Integration Inventory:",
    "",
    "| Integration | Confidence | Directionality | Auth Method | Vendor Evidence |",
    "|---|---|---|---|---|",
    integrationRows,
    "",
    "Attached Documents:",
    "",
    "| Document | Kind | Status | Notes |",
    "|---|---|---|---|",
    docRows,
    "",
    "## Section 1.0 Executive Summary",
    "",
    `${vendor} was assessed from the available scope and attached documents. This draft is evidence-limited and must be reviewed by a human before any approval or vendor communication.`,
    "",
    "Evidence Highlights:",
    "",
    evidenceHighlightText,
    "",
    "Evidence Limits:",
    "",
    limitationText,
    "",
    "Validation Notes:",
    "",
    validationWarning,
    "",
    "## Section 2.0 Critical Security & Legal Exceptions (Red Flags)",
    "",
    exceptionText,
    "",
    "## Section 3.0 External References & Link Verification",
    "",
    "The following references appeared in the attached evidence. This local module run did not independently verify link freshness or private artifact contents:",
    "",
    referenceText,
    "",
    "## Section 4.0 Detailed Domain Analysis",
    "",
    json.weaknesses
      .map((w) => `- ${w.id} (${w.severity}, ${w.confidence} confidence): ${w.summary}`)
      .join("\n") || "No document-backed weaknesses were generated by the fallback path.",
    "",
    "## Section 5.0 Required Mitigations & Integration Best Practices",
    "",
    json.mitigations.map((m, i) => `${i + 1}. ${m}`).join("\n"),
    "",
    "## Section 6.0 Vendor Clarification Addendum",
    "",
    json.questions.map((q, i) => `${i + 1}. ${q}`).join("\n"),
    "",
    "## Appendix: Machine-readable summary",
    "",
    "```json",
    JSON.stringify(
      {
        overallRisk: json.overallRisk,
        criticalIntegrations: json.criticalIntegrations,
        completenessGateFailed: json.completenessGate.failed,
        missingArtifacts: json.completenessGate.missingArtifacts,
        weaknessCount: json.weaknesses.length,
        questionCount: json.questions.length,
      },
      null,
      2,
    ),
    "```",
  ].join("\n");
}

function normalizeAppendix(raw: Record<string, unknown>): Partial<VendorAssessmentReportJson> {
  const out: Partial<VendorAssessmentReportJson> = {};
  if (isRisk(raw.overallRisk)) out.overallRisk = raw.overallRisk;
  if (isRisk(raw.overall_risk)) out.overallRisk = raw.overall_risk;
  if (Array.isArray(raw.criticalIntegrations)) {
    out.criticalIntegrations = raw.criticalIntegrations.filter(
      (item): item is string => typeof item === "string",
    );
  }
  if (Array.isArray(raw.critical_platforms)) {
    out.criticalIntegrations = raw.critical_platforms.filter(
      (item): item is string => typeof item === "string",
    );
  }
  return out;
}

function isRisk(value: unknown): value is VendorAssessmentReportJson["overallRisk"] {
  return value === "Critical" || value === "High" || value === "Medium" || value === "Low";
}

function titleCase(value: string): string {
  return value.slice(0, 1).toUpperCase() + value.slice(1);
}

function collectEvidenceHighlights(scope: VendorAssessmentScope): string[] {
  const patterns = [
    /\b(SOC 2|ISO \d+|PCI|GDPR|DPF|TX-RAMP|SSO|SAML|RBAC|role-based)\b/i,
    /\b(processor|service provider|personal data|privacy policy)\b/i,
    /\b(integration|sync|API key|API credentials?|credentials?|OAuth|token)\b/i,
    /\b(does not include|does not describe|not describe|limitation|missing|not supplied)\b/i,
  ];
  const highlights: string[] = [];
  for (const [index, pattern] of patterns.entries()) {
    const line = findEvidenceLine(scope, [pattern], highlights, {
      avoid:
        index === 0
          ? /\b(does not include|does not describe|not describe|limitation|missing|not supplied)\b/i
          : undefined,
    });
    if (line) highlights.push(line);
  }
  for (const integration of scope.integrations) {
    const line = findEvidenceLine(
      scope,
      [new RegExp(`\\b${escapeRegExp(integration)}\\b`, "i")],
      highlights,
    );
    if (line) highlights.push(line);
    if (highlights.length >= 8) break;
  }
  return highlights.slice(0, 8);
}

function collectEvidenceLimitations(
  json: VendorAssessmentReportJson,
  scope: VendorAssessmentScope,
): string[] {
  const limitations = new Set<string>();
  if (json.completenessGate.missingArtifacts.length > 0) {
    limitations.add(`Missing artifacts: ${json.completenessGate.missingArtifacts.join(", ")}.`);
  }
  if (!scope.documents.some((doc) => doc.kind === "questionnaire")) {
    limitations.add("No security questionnaire was attached.");
  }
  const limitationEvidence =
    findEvidenceLine(scope, [/^Assessment limitation:/i]) ??
    findEvidenceLine(scope, [/\b(does not include|does not describe|not describe|limitation)\b/i]);
  if (limitationEvidence) limitations.add(limitationEvidence);
  if (scope.documents.length === 0) {
    limitations.add("No documents were attached; this is an intake packet only.");
  }
  if (limitations.size === 0) {
    limitations.add("No explicit evidence limitations were identified by the fallback renderer.");
  }
  return [...limitations];
}

function collectReferenceLinks(scope: VendorAssessmentScope): string[] {
  const urls = new Set<string>();
  for (const doc of scope.documents) {
    if (doc.sourceType === "url") urls.add(doc.source);
    const text = doc.extracted?.text ?? "";
    for (const match of text.matchAll(/https?:\/\/[^\s>)\]]+/g)) {
      const value = match[0]?.replace(/[.,;:]+$/g, "");
      if (value) urls.add(value);
    }
  }
  return [...urls].slice(0, 20);
}

function findEvidenceLine(
  scope: VendorAssessmentScope,
  patterns: RegExp[],
  excluding: string[] = [],
  options: { avoid?: RegExp } = {},
): string | undefined {
  const excluded = new Set(excluding.map((line) => normalizeText(line).toLowerCase()));
  for (const item of evidenceLines(scope)) {
    if (!patterns.some((pattern) => pattern.test(item.line))) continue;
    if (options.avoid?.test(item.line)) continue;
    const rendered = `${item.title}: ${item.line}`;
    const truncated = truncateForReport(rendered, 260);
    if (excluded.has(normalizeText(truncated).toLowerCase())) continue;
    return truncated;
  }
  return undefined;
}

function evidenceLines(scope: VendorAssessmentScope): Array<{ title: string; line: string }> {
  const lines: Array<{ title: string; line: string }> = [];
  for (const doc of scope.documents) {
    const text = doc.extracted?.text ?? "";
    for (const rawLine of text.split(/\n+/)) {
      if (/^\s*#+\s+/.test(rawLine)) continue;
      if (/^\s*[-*]\s*[^:]{1,80}:\s*https?:\/\//i.test(rawLine)) continue;
      const line = normalizeText(rawLine.replace(/^[-*#\d.\s]+/, ""));
      if (line.length < 24) continue;
      lines.push({ title: doc.title, line });
    }
  }
  return lines;
}

function summarizeAuthEvidence(evidence: string | undefined): string {
  if (!evidence) return "Not disclosed";
  const lower = evidence.toLowerCase();
  const tags: string[] = [];
  if (/\boauth\b/.test(lower)) tags.push("OAuth");
  if (/\bapi key\b/.test(lower)) tags.push("API key");
  if (/\bapi credentials?\b/.test(lower)) tags.push("API credentials");
  else if (/\bcredentials?\b/.test(lower)) tags.push("Credentials");
  if (/\btoken\b/.test(lower)) tags.push("Token");
  if (/\bsaml\b/.test(lower)) tags.push("SAML");
  if (/\bsso\b/.test(lower)) tags.push("SSO");
  return tags.length > 0 ? tags.join(", ") : "Referenced, details unclear";
}

function tableCell(value: string): string {
  return truncateForReport(normalizeText(value).replace(/\|/g, "/"), 180);
}

function truncateForReport(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value;
  return `${value.slice(0, Math.max(0, maxLength - 3)).trimEnd()}...`;
}

function normalizeText(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

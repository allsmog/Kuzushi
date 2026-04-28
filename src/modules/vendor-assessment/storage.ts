import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { DEFAULT_VENDOR_ASSESSMENT_PROFILE } from "./profiles.js";
import type {
  VendorAssessmentDocument,
  VendorAssessmentHomeSlice,
  VendorAssessmentReportJson,
  VendorAssessmentScope,
} from "./types.js";

export function vendorAssessmentRoot(cwd: string): string {
  return path.join(cwd, ".kuzushi", "vendor-assessment");
}

export function draftScopePath(cwd: string): string {
  return path.join(vendorAssessmentRoot(cwd), "scope.draft.json");
}

export function runRoot(cwd: string, runId: string): string {
  return path.join(vendorAssessmentRoot(cwd), "runs", runId);
}

export function promptsDir(cwd: string, runId: string): string {
  return path.join(runRoot(cwd, runId), "prompts");
}

export function createEmptyScope(
  profile = DEFAULT_VENDOR_ASSESSMENT_PROFILE,
): VendorAssessmentScope {
  return {
    profile,
    dataClasses: [],
    integrations: [],
    documents: [],
    updatedAt: new Date().toISOString(),
  };
}

export function loadDraftScope(cwd: string): VendorAssessmentScope {
  const file = draftScopePath(cwd);
  if (!existsSync(file)) return createEmptyScope();
  const raw = JSON.parse(readFileSync(file, "utf-8")) as Partial<VendorAssessmentScope>;
  return normalizeScope(raw);
}

export function saveDraftScope(cwd: string, scope: VendorAssessmentScope): string {
  const file = draftScopePath(cwd);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(
    file,
    `${JSON.stringify({ ...scope, updatedAt: new Date().toISOString() }, null, 2)}\n`,
  );
  return file;
}

export function clearDraftScope(cwd: string): void {
  const file = draftScopePath(cwd);
  if (existsSync(file)) rmSync(file);
}

export function upsertDocument(
  scope: VendorAssessmentScope,
  doc: VendorAssessmentDocument,
): VendorAssessmentScope {
  const docs = scope.documents.filter((existing) => existing.id !== doc.id);
  docs.push(doc);
  return { ...scope, documents: docs, updatedAt: new Date().toISOString() };
}

export function writeRunArtifacts(input: {
  cwd: string;
  runId: string;
  scope: VendorAssessmentScope;
  reportMarkdown: string;
  reportJson: VendorAssessmentReportJson;
  prompts: ReadonlyArray<{ fileName: string; content: string }>;
}): VendorAssessmentReportJson["artifacts"] {
  const root = runRoot(input.cwd, input.runId);
  const promptRoot = promptsDir(input.cwd, input.runId);
  mkdirSync(promptRoot, { recursive: true });

  const scopePath = path.join(root, "scope.json");
  const reportPath = path.join(root, "report.md");
  const reportJsonPath = path.join(root, "report.json");
  writeFileSync(scopePath, `${JSON.stringify(input.scope, null, 2)}\n`);
  writeFileSync(
    reportPath,
    input.reportMarkdown.endsWith("\n") ? input.reportMarkdown : `${input.reportMarkdown}\n`,
  );
  writeFileSync(reportJsonPath, `${JSON.stringify(input.reportJson, null, 2)}\n`);
  for (const prompt of input.prompts) {
    writeFileSync(
      path.join(promptRoot, prompt.fileName),
      prompt.content.endsWith("\n") ? prompt.content : `${prompt.content}\n`,
    );
  }

  return {
    scopePath,
    reportPath,
    reportJsonPath,
    promptsDir: promptRoot,
  };
}

export function scopeToHomeSlice(
  cwd: string,
  scope: VendorAssessmentScope,
  lastRun?: VendorAssessmentHomeSlice["lastRun"],
): VendorAssessmentHomeSlice {
  const missingArtifacts = missingArtifactsForHome(scope);
  const hasParsedText = scope.documents.some((doc) => (doc.extracted?.charCount ?? 0) >= 100);
  const confidence =
    scope.documents.length === 0 ? "empty" : hasParsedText ? "document-backed" : "low";
  return {
    scopePath: draftScopePath(cwd),
    vendorName: scope.vendorName,
    profile: scope.profile,
    confidence,
    documents: scope.documents.map((doc) => ({
      title: doc.title,
      kind: doc.kind,
      status: doc.status,
      detail:
        doc.status === "parsed"
          ? `${doc.extracted?.charCount ?? 0} chars`
          : (doc.parseWarnings[0] ?? doc.status),
    })),
    missingArtifacts,
    ...(lastRun ? { lastRun } : {}),
  };
}

function normalizeScope(raw: Partial<VendorAssessmentScope>): VendorAssessmentScope {
  return {
    vendorName: stringOrUndefined(raw.vendorName),
    productName: stringOrUndefined(raw.productName),
    primaryDomain: stringOrUndefined(raw.primaryDomain),
    useCase: stringOrUndefined(raw.useCase),
    profile: stringOrUndefined(raw.profile) ?? DEFAULT_VENDOR_ASSESSMENT_PROFILE,
    dataClasses: stringArray(raw.dataClasses),
    integrations: stringArray(raw.integrations),
    documents: Array.isArray(raw.documents)
      ? raw.documents.filter((doc): doc is VendorAssessmentDocument => {
          return Boolean(doc && typeof doc === "object" && typeof doc.id === "string");
        })
      : [],
    updatedAt: stringOrUndefined(raw.updatedAt) ?? new Date().toISOString(),
  };
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function missingArtifactsForHome(scope: VendorAssessmentScope): string[] {
  const missing: string[] = [];
  if (!scope.useCase) missing.push("use case statement");
  if (scope.integrations.length === 0) missing.push("integration inventory");
  if (!scope.documents.some((doc) => doc.kind === "diagram")) missing.push("architecture diagram");
  if (!scope.documents.some((doc) => doc.kind === "questionnaire"))
    missing.push("security questionnaire");
  return missing;
}

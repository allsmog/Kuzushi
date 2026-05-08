import { existsSync, mkdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { defineModule, defineTool } from "../define.js";
import type { CopilotModule, ExecutionContext, ToolResult } from "../types.js";
import { attachDocument } from "./documents.js";
import { getVendorAssessmentProfile, listVendorAssessmentProfiles } from "./profiles.js";
import { buildVendorAssessmentPrompts } from "./prompts.js";
import {
  assessCompleteness,
  buildFallbackReport,
  hasMeaningfulDocumentText,
  mergeReportJson,
} from "./report.js";
import {
  clearDraftScope,
  createEmptyScope,
  draftScopePath,
  loadDraftScope,
  promptsDir,
  runRoot,
  saveDraftScope,
  scopeToHomeSlice,
  upsertDocument,
  writeRunArtifacts,
} from "./storage.js";
import type {
  VendorAssessmentHomeSlice,
  VendorAssessmentReportJson,
  VendorAssessmentScope,
} from "./types.js";

interface AttachInput {
  source?: string;
  path?: string;
  url?: string;
  target?: string;
  kind?: string;
  title?: string;
  vendorName?: string;
  productName?: string;
  primaryDomain?: string;
  useCase?: string;
  profile?: string;
  dataClasses?: unknown;
  integrations?: unknown;
}

interface ScopeInput {
  clear?: boolean;
  target?: string;
}

interface AssessInput {
  vendorName?: string;
  vendor?: string;
  productName?: string;
  domain?: string;
  primaryDomain?: string;
  useCase?: string;
  profile?: string;
  dataClasses?: unknown;
  integrations?: unknown;
  model?: string;
  target?: string;
}

interface PromptsInput extends AssessInput {
  runId?: string;
}

const attachTool = defineTool<"vendor-assessment">({
  name: "vendor-assessment:attach",
  displayName: "Attach Vendor Document",
  formatInput(input) {
    const params = input as AttachInput | undefined;
    return params?.source ?? params?.path ?? params?.url ?? params?.target ?? null;
  },
  renderResult(result) {
    return result.output.split("\n", 1)[0] ?? null;
  },
  description:
    "Attach a local file or URL to the current vendor assessment draft scope. Text, Markdown, JSON, CSV, and lightweight PDF text are parsed when possible.",
  inputSchema: {
    type: "object",
    properties: {
      source: { type: "string", description: "Local path or URL to attach." },
      path: { type: "string", description: "Alias for source." },
      url: { type: "string", description: "Alias for source." },
      target: { type: "string", description: "Positional alias for source." },
      kind: {
        type: "string",
        enum: [
          "questionnaire",
          "diagram",
          "transcript",
          "contract",
          "policy",
          "security-report",
          "other",
        ],
        description: "Optional document kind override.",
      },
      title: { type: "string", description: "Optional display title." },
      vendorName: { type: "string", description: "Vendor name to store on the draft scope." },
      productName: { type: "string", description: "Product name to store on the draft scope." },
      primaryDomain: { type: "string", description: "Primary vendor domain." },
      useCase: { type: "string", description: "Intended enterprise use case." },
      profile: { type: "string", description: "Assessment profile id. Defaults to enterprise-ai." },
      dataClasses: {
        type: "array",
        items: { type: "string" },
        description: "Data classes in scope.",
      },
      integrations: {
        type: "array",
        items: { type: "string" },
        description: "Known integrations.",
      },
    },
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = readAttachInput(input);
    const source = params.source ?? params.path ?? params.url ?? params.target;
    if (!source?.trim()) {
      return {
        ok: false,
        output: "Usage: attach <path-or-url> [kind=questionnaire|diagram|transcript|contract]",
      };
    }

    const cwd = assessmentCwd(ctx);
    let scope = mergeScopeInputs(loadDraftScope(cwd), params);
    const doc = attachDocument({ source, cwd, kind: params.kind, title: params.title });
    scope = upsertDocument(scope, doc);
    const scopePath = saveDraftScope(cwd, scope);
    patchHome(ctx, cwd, scope);

    const lines = [`Attached ${doc.title} (${doc.kind}, ${doc.status}).`, `Scope: ${scopePath}`];
    if (doc.parseWarnings.length > 0) {
      lines.push("Warnings:");
      for (const warning of doc.parseWarnings) lines.push(`  - ${warning}`);
    }
    return { ok: doc.status !== "error", output: lines.join("\n"), data: { scope, document: doc } };
  },
});

const scopeTool = defineTool<"vendor-assessment">({
  name: "vendor-assessment:scope",
  displayName: "Vendor Scope",
  formatInput(input) {
    const params = input as ScopeInput | undefined;
    return params?.clear ? "clear" : "show";
  },
  description: "Show or clear the current vendor assessment draft scope.",
  inputSchema: {
    type: "object",
    properties: {
      clear: { type: "boolean", description: "Clear the draft scope when true." },
      target: { type: "string", description: "Shell target passthrough." },
    },
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = readScopeInput(input);
    const cwd = assessmentCwd(ctx);
    if (params.clear) {
      clearDraftScope(cwd);
      patchHome(ctx, cwd, createEmptyScope());
      return {
        ok: true,
        output: "Vendor assessment draft scope cleared.",
        data: { cleared: true },
      };
    }
    const scope = loadDraftScope(cwd);
    patchHome(ctx, cwd, scope);
    return { ok: true, output: formatScope(scope, draftScopePath(cwd)), data: { scope } };
  },
});

const promptsTool = defineTool<"vendor-assessment">({
  name: "vendor-assessment:prompts",
  displayName: "Vendor Prompts",
  formatInput(input) {
    const params = input as PromptsInput | undefined;
    return params?.profile ?? null;
  },
  description:
    "Generate downstream-agent prompt bundles for the current vendor assessment scope without running the assessment.",
  inputSchema: {
    type: "object",
    properties: {
      runId: { type: "string", description: "Optional run id for the prompt artifact directory." },
      target: { type: "string", description: "Shell target passthrough." },
      vendorName: { type: "string", description: "Vendor name to store on the draft scope." },
      vendor: { type: "string", description: "Alias for vendorName." },
      productName: { type: "string", description: "Product name." },
      domain: { type: "string", description: "Alias for primaryDomain." },
      primaryDomain: { type: "string", description: "Primary vendor domain." },
      useCase: { type: "string", description: "Intended enterprise use case." },
      profile: { type: "string", description: "Assessment profile id. Defaults to enterprise-ai." },
      dataClasses: {
        type: "array",
        items: { type: "string" },
        description: "Data classes in scope.",
      },
      integrations: {
        type: "array",
        items: { type: "string" },
        description: "Known integrations.",
      },
    },
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = readPromptsInput(input);
    const cwd = assessmentCwd(ctx);
    const scope = mergeScopeInputs(loadDraftScope(cwd), params);
    saveDraftScope(cwd, scope);
    patchHome(ctx, cwd, scope);

    const profile = getVendorAssessmentProfile(scope.profile);
    const runId = params.runId?.trim() || createRunId("prompts");
    const bundle = buildVendorAssessmentPrompts(scope, profile);
    const outDir = promptsDir(cwd, runId);
    mkdirSync(outDir, { recursive: true });
    for (const prompt of bundle.prompts) {
      writeFileSync(path.join(outDir, prompt.fileName), `${prompt.content}\n`);
    }

    const lines = [
      `Prompt bundle written to ${outDir}`,
      `Profile: ${profile.id}`,
      `Prompts: ${bundle.prompts.length}`,
    ];
    return {
      ok: true,
      output: lines.join("\n"),
      data: { runId, promptsDir: outDir, prompts: bundle.prompts },
    };
  },
});

const assessTool = defineTool<"vendor-assessment">({
  name: "vendor-assessment:assess",
  displayName: "Vendor Assessment",
  formatInput(input) {
    const params = input as AssessInput | undefined;
    return params?.vendorName ?? params?.vendor ?? params?.domain ?? params?.primaryDomain ?? null;
  },
  renderResult(result) {
    if (!result.ok) return result.output.split("\n", 1)[0] ?? null;
    const data = result.data as { report?: VendorAssessmentReportJson } | undefined;
    return data?.report
      ? `${data.report.overallRisk} · ${data.report.confidence} · ${data.report.documents.length} document(s)`
      : (result.output.split("\n", 1)[0] ?? null);
  },
  description:
    "Run the vendor assessment using the current draft scope plus inline inputs. Produces report.md, report.json, scope.json, and prompt artifacts.",
  inputSchema: {
    type: "object",
    properties: {
      vendorName: { type: "string", description: "Vendor name." },
      vendor: { type: "string", description: "Alias for vendorName." },
      productName: { type: "string", description: "Product name." },
      domain: { type: "string", description: "Alias for primaryDomain." },
      primaryDomain: { type: "string", description: "Primary vendor domain." },
      useCase: { type: "string", description: "Intended enterprise use case." },
      profile: { type: "string", description: "Assessment profile id. Defaults to enterprise-ai." },
      dataClasses: {
        type: "array",
        items: { type: "string" },
        description: "Data classes in scope.",
      },
      integrations: {
        type: "array",
        items: { type: "string" },
        description: "Known integrations.",
      },
      model: { type: "string", description: "Model override for this assessment." },
      target: { type: "string", description: "Shell target passthrough." },
    },
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = readAssessInput(input);
    const cwd = assessmentCwd(ctx);
    const runId = createRunId("va");
    const scope = mergeScopeInputs(loadDraftScope(cwd), params);
    saveDraftScope(cwd, scope);
    patchHome(ctx, cwd, scope);

    const profile = getVendorAssessmentProfile(scope.profile);
    const bundle = buildVendorAssessmentPrompts(scope, profile);
    const mode = hasMeaningfulDocumentText(scope) ? "document-backed" : "intake";
    const root = runRoot(cwd, runId);
    const artifactPaths: VendorAssessmentReportJson["artifacts"] = {
      scopePath: path.join(root, "scope.json"),
      reportPath: path.join(root, "report.md"),
      reportJsonPath: path.join(root, "report.json"),
      promptsDir: promptsDir(cwd, runId),
    };

    updateSteps(ctx, [
      step("ingest", "ingest documents", "done", `${scope.documents.length} doc(s)`),
      step("completeness", "completeness gate", "running"),
      step("inventory", "integration inventory", "pending"),
      step("domains", "domain review", "pending"),
      step("mitigations", "synthesize mitigations", "pending"),
      step("validate", "validate report JSON", "pending"),
    ]);
    const gate = assessCompleteness(scope, profile);
    updateSteps(ctx, [
      step("ingest", "ingest documents", "done", `${scope.documents.length} doc(s)`),
      step("completeness", "completeness gate", "done", `${gate.missingArtifacts.length} missing`),
      step(
        "inventory",
        "integration inventory",
        "running",
        `${scope.integrations.length} declared`,
      ),
      step("domains", "domain review", "pending"),
      step("mitigations", "synthesize mitigations", "pending"),
      step("validate", "validate report JSON", "pending"),
    ]);

    let costUsd = 0;
    let modelMarkdown = "";
    if (mode === "document-backed") {
      ctx.reportActivity?.("running vendor assessment model", { phase: "domain-review" });
      const modelResult = await runModel(bundle.combinedPrompt, ctx, params.model);
      modelMarkdown = modelResult.output.trim();
      costUsd += modelResult.costUsd;
    }

    updateSteps(ctx, [
      step("ingest", "ingest documents", "done", `${scope.documents.length} doc(s)`),
      step("completeness", "completeness gate", "done", `${gate.missingArtifacts.length} missing`),
      step("inventory", "integration inventory", "done", `${scope.integrations.length} declared`),
      step("domains", "domain review", "done"),
      step("mitigations", "synthesize mitigations", "running"),
      step("validate", "validate report JSON", "pending"),
    ]);

    const fallback = buildFallbackReport({
      runId,
      scope,
      profile,
      mode,
      artifacts: artifactPaths,
    });
    const useModelMarkdown =
      modelMarkdown.includes("Vendor AI Security Assessment Report") &&
      modelMarkdown.includes("Appendix");
    const reportMarkdown = useModelMarkdown ? modelMarkdown : fallback.markdown;
    let reportJson = useModelMarkdown
      ? mergeReportJson({ base: fallback.json, markdown: reportMarkdown })
      : fallback.json;
    const artifacts = artifactPaths;
    reportJson = { ...reportJson, artifacts };
    writeRunArtifacts({
      cwd,
      runId,
      scope,
      reportMarkdown,
      reportJson,
      prompts: bundle.prompts,
    });

    updateSteps(ctx, [
      step("ingest", "ingest documents", "done", `${scope.documents.length} doc(s)`),
      step("completeness", "completeness gate", "done", `${gate.missingArtifacts.length} missing`),
      step("inventory", "integration inventory", "done", `${scope.integrations.length} declared`),
      step("domains", "domain review", "done"),
      step(
        "mitigations",
        "synthesize mitigations",
        "done",
        `${reportJson.mitigations.length} item(s)`,
      ),
      step("validate", "validate report JSON", "done"),
    ]);
    ctx.uiStore?.patchModuleRun?.({
      costUsd,
      artifacts: [
        { label: "report.md", path: artifacts.reportPath },
        { label: "report.json", path: artifacts.reportJsonPath },
        { label: "scope.json", path: artifacts.scopePath },
        { label: "prompts", path: artifacts.promptsDir },
      ],
    });
    patchHome(ctx, cwd, scope, {
      runId,
      overallRisk: reportJson.overallRisk,
      reportPath: artifacts.reportPath,
    });

    const lines = [
      `Vendor assessment complete (${reportJson.overallRisk}, ${reportJson.confidence}).`,
      `Report: ${artifacts.reportPath}`,
      `JSON:   ${artifacts.reportJsonPath}`,
      `Scope:  ${artifacts.scopePath}`,
      `Prompts: ${artifacts.promptsDir}`,
    ];
    return { ok: true, output: lines.join("\n"), data: { report: reportJson, scope }, costUsd };
  },
});

export function createVendorAssessmentModule(): CopilotModule {
  return defineModule({
    id: "vendor-assessment",
    displayName: "Vendor Assessment",
    category: "governance",
    version: "0.1.0",
    description:
      "Evidence-first vendor assessment workflow with attachment-backed scope and gated reports.",
    longDescription: "Includes prompt bundles, completeness gates, and local report artifacts.",
    rank: "normal",
    tools: [attachTool, scopeTool, assessTool, promptsTool],
    async init() {
      // No external adapters are initialized in v1.
    },
    async dispose() {
      // Nothing to release.
    },
  });
}

function assessmentCwd(ctx: ExecutionContext): string {
  if (ctx.target && !/^[a-z][a-z0-9+.-]*:\/\//i.test(ctx.target)) {
    const targetPath = path.resolve(ctx.cwd, ctx.target);
    try {
      if (existsSync(targetPath) && statSync(targetPath).isDirectory()) return targetPath;
    } catch {
      // Positional attach sources can arrive as ctx.target. Persist under cwd
      // unless the target is a real directory.
    }
  }
  return path.resolve(ctx.cwd);
}

function mergeScopeInputs<T extends Partial<AssessInput & AttachInput>>(
  scope: VendorAssessmentScope,
  input: T,
): VendorAssessmentScope {
  return {
    ...scope,
    vendorName: stringValue(input.vendorName) ?? stringValue(input.vendor) ?? scope.vendorName,
    productName: stringValue(input.productName) ?? scope.productName,
    primaryDomain:
      stringValue(input.primaryDomain) ?? stringValue(input.domain) ?? scope.primaryDomain,
    useCase: stringValue(input.useCase) ?? scope.useCase,
    profile: stringValue(input.profile) ?? scope.profile,
    dataClasses: mergeStringList(scope.dataClasses, input.dataClasses),
    integrations: mergeStringList(scope.integrations, input.integrations),
    updatedAt: new Date().toISOString(),
  };
}

async function runModel(
  prompt: string,
  ctx: ExecutionContext,
  modelOverride?: string,
): Promise<{ output: string; costUsd: number }> {
  const model = modelOverride ?? ctx.toolModel ?? ctx.config.model;
  let output = "";
  let costUsd = 0;
  for await (const message of ctx.runtime.query({
    prompt,
    options: {
      cwd: ctx.cwd,
      model,
      permissionMode: "dontAsk",
      allowedTools: [],
      abortController: ctx.signal ? signalToAbortController(ctx.signal) : undefined,
      taskId: "vendor-assessment",
    },
  })) {
    if (message.type === "result") {
      if (message.subtype === "success" && "result" in message) output = message.result;
      if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
        costUsd += message.totalCostUsd;
      }
    }
  }
  return { output, costUsd };
}

function signalToAbortController(signal: AbortSignal): AbortController {
  const controller = new AbortController();
  if (signal.aborted) controller.abort();
  else signal.addEventListener("abort", () => controller.abort(), { once: true });
  return controller;
}

function patchHome(
  ctx: ExecutionContext,
  cwd: string,
  scope: VendorAssessmentScope,
  lastRun?: VendorAssessmentHomeSlice["lastRun"],
): void {
  const state = ctx.uiStore?.getState();
  if (!state || typeof state !== "object" || !("shell" in state)) return;
  const shell = (state as { shell?: unknown }).shell;
  if (!shell || typeof shell !== "object") return;
  ctx.uiStore?.update({
    shell: {
      ...(shell as Record<string, unknown>),
      vendorAssessment: scopeToHomeSlice(cwd, scope, lastRun),
    },
  });
}

function updateSteps(
  ctx: ExecutionContext,
  steps: Array<{
    id: string;
    title: string;
    status: "pending" | "running" | "done" | "error";
    count?: string;
  }>,
): void {
  ctx.uiStore?.setModuleRunSteps?.(steps);
}

function step(
  id: string,
  title: string,
  status: "pending" | "running" | "done" | "error",
  count?: string,
): { id: string; title: string; status: "pending" | "running" | "done" | "error"; count?: string } {
  return count ? { id, title, status, count } : { id, title, status };
}

function formatScope(scope: VendorAssessmentScope, scopePath: string): string {
  const lines = [
    `Scope: ${scopePath}`,
    `Vendor: ${scope.vendorName ?? "(not set)"}`,
    `Product: ${scope.productName ?? "(not set)"}`,
    `Domain: ${scope.primaryDomain ?? "(not set)"}`,
    `Profile: ${scope.profile}`,
    `Use case: ${scope.useCase ?? "(not set)"}`,
    `Data classes: ${scope.dataClasses.join(", ") || "(not set)"}`,
    `Integrations: ${scope.integrations.join(", ") || "(not set)"}`,
    `Documents: ${scope.documents.length}`,
  ];
  for (const doc of scope.documents) {
    lines.push(`  - ${doc.title} (${doc.kind}, ${doc.status})`);
  }
  return lines.join("\n");
}

function createRunId(prefix: string): string {
  const stamp = new Date()
    .toISOString()
    .replace(/[-:.TZ]/g, "")
    .slice(0, 14);
  return `${prefix}-${stamp}-${Math.random().toString(36).slice(2, 6)}`;
}

function readAttachInput(input: unknown): AttachInput {
  return isObject(input) ? (input as AttachInput) : {};
}

function readScopeInput(input: unknown): ScopeInput {
  return isObject(input) ? (input as ScopeInput) : {};
}

function readAssessInput(input: unknown): AssessInput {
  return isObject(input) ? (input as AssessInput) : {};
}

function readPromptsInput(input: unknown): PromptsInput {
  return isObject(input) ? (input as PromptsInput) : {};
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function mergeStringList(current: string[], value: unknown): string[] {
  const next = new Set(current);
  const values = Array.isArray(value) ? value : typeof value === "string" ? value.split(",") : [];
  for (const item of values) {
    if (typeof item === "string" && item.trim().length > 0) next.add(item.trim());
  }
  return [...next];
}

export const __vendorAssessmentInternals = {
  assessCompleteness,
  attachDocument,
  buildVendorAssessmentPrompts,
  getVendorAssessmentProfile,
  hasMeaningfulDocumentText,
  listVendorAssessmentProfiles,
};

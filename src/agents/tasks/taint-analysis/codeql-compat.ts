import { execFile, type ExecFileException } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { toErrorMessage } from "../../../utils.js";
import type { TaintAnalysisLanguage } from "./types.js";

const execFileAsync = promisify(execFile);

export type CodeqlProfileId = string;

export interface CodeqlProfile {
  id: CodeqlProfileId;
  language: TaintAnalysisLanguage;
  dataFlowImport: string;
  taintTrackingImport: string;
  /**
   * The CodeQL type used for call nodes in `exists(...)` clauses.
   * Defaults to `"DataFlow::CallNode"` (Go, Java, C#).
   * Python uses `"CallCfgNode"` (top-level, not under `DataFlow::`).
   * JavaScript uses `"DataFlow::InvokeNode"`.
   */
  callNodeType?: string;
  /**
   * Method name for getting a positional argument.
   * Defaults to `"getArgument"` (Go, Java, C#, JS).
   * Python uses `"getArg"`.
   */
  getArgumentMethod?: string;
  /**
   * Method name for getting any argument.
   * Defaults to `"getAnArgument"` (Go, Java, C#, JS).
   * Python uses `"getAnArg"` — but it doesn't exist, so we use `"getArg(_)"`.
   */
  getAnArgumentExpr?: string;
  /**
   * Expression to get the call's return/result value as a DataFlow::Node.
   * Defaults to `"call.getResult()"` (Go).
   * Python: `"call"` (the CallCfgNode itself is a DataFlow::Node).
   * JavaScript: `"call"` (InvokeNode extends Node).
   */
  callResultExpr?: string;
  /**
   * How to match a callee name. Uses `{NAME}` as placeholder.
   * Defaults to `"call.getCalleeName() = \"{NAME}\""`.
   * Python: match via MethodCallNode or function attribute.
   */
  calleeNamePattern?: string;
}

interface ProbeArgs {
  codeqlBinary: string;
  workspaceDir: string;
  probeTimeoutMs?: number;
}

interface DetectWorkingProfileArgs extends ProbeArgs {
  language: TaintAnalysisLanguage;
  codeqlApiProfile?: "auto" | string;
  codeqlProfileFallbacks?: boolean;
  validate?: (profile: CodeqlProfile, args: ProbeArgs) => Promise<void>;
}

export interface DetectWorkingProfileResult {
  selected: CodeqlProfile;
  tried: Array<{ id: string; ok: boolean; error?: string }>;
}

export class CodeqlProfileDetectionError extends Error {
  readonly tried: Array<{ id: string; ok: boolean; error?: string }>;

  constructor(message: string, tried: Array<{ id: string; ok: boolean; error?: string }>) {
    super(message);
    this.name = "CodeqlProfileDetectionError";
    this.tried = tried;
  }
}

const PROFILE_MATRIX: Record<TaintAnalysisLanguage, CodeqlProfile[]> = {
  go: [
    {
      id: "go-dataflow",
      language: "go",
      dataFlowImport: "semmle.go.dataflow.DataFlow",
      taintTrackingImport: "semmle.go.dataflow.TaintTracking",
    },
    {
      id: "go-dataflow-new",
      language: "go",
      dataFlowImport: "semmle.go.dataflow.new.DataFlow",
      taintTrackingImport: "semmle.go.dataflow.new.TaintTracking",
    },
  ],
  python: [
    {
      id: "python-dataflow-new",
      language: "python",
      dataFlowImport: "semmle.python.dataflow.new.DataFlow",
      taintTrackingImport: "semmle.python.dataflow.new.TaintTracking",
      callNodeType: "DataFlow::CallCfgNode",
      getArgumentMethod: "getArg",
      getAnArgumentExpr: "call.getArg(_)",
      callResultExpr: "call",
      calleeNamePattern: "call.getFunction().toString().matches(\"%{NAME}%\")",
    },
    {
      id: "python-dataflow-old",
      language: "python",
      dataFlowImport: "semmle.python.dataflow.old.DataFlow",
      taintTrackingImport: "semmle.python.dataflow.old.TaintTracking",
      callNodeType: "DataFlow::CallCfgNode",
      getArgumentMethod: "getArg",
      getAnArgumentExpr: "call.getArg(_)",
      callResultExpr: "call",
      calleeNamePattern: "call.getFunction().toString().matches(\"%{NAME}%\")",
    },
  ],
  java: [
    {
      id: "java-dataflow",
      language: "java",
      dataFlowImport: "semmle.code.java.dataflow.DataFlow",
      taintTrackingImport: "semmle.code.java.dataflow.TaintTracking",
    },
    {
      id: "java-dataflow-new",
      language: "java",
      dataFlowImport: "semmle.code.java.dataflow.new.DataFlow",
      taintTrackingImport: "semmle.code.java.dataflow.new.TaintTracking",
    },
  ],
  javascript: [
    {
      id: "javascript-dataflow",
      language: "javascript",
      dataFlowImport: "semmle.javascript.dataflow.DataFlow",
      taintTrackingImport: "semmle.javascript.dataflow.TaintTracking",
      callNodeType: "DataFlow::InvokeNode",
      callResultExpr: "call",
    },
    {
      id: "javascript-dataflow-new",
      language: "javascript",
      dataFlowImport: "semmle.javascript.dataflow.new.DataFlow",
      taintTrackingImport: "semmle.javascript.dataflow.new.TaintTracking",
      callNodeType: "DataFlow::InvokeNode",
      callResultExpr: "call",
    },
  ],
  csharp: [
    {
      id: "csharp-dataflow",
      language: "csharp",
      dataFlowImport: "semmle.code.csharp.dataflow.DataFlow",
      taintTrackingImport: "semmle.code.csharp.dataflow.TaintTracking",
    },
    {
      id: "csharp-dataflow-new",
      language: "csharp",
      dataFlowImport: "semmle.code.csharp.dataflow.new.DataFlow",
      taintTrackingImport: "semmle.code.csharp.dataflow.new.TaintTracking",
    },
  ],
};

export function candidateProfiles(language: TaintAnalysisLanguage): CodeqlProfile[] {
  return PROFILE_MATRIX[language].map((profile) => ({ ...profile }));
}

export function profileById(language: TaintAnalysisLanguage, id: string): CodeqlProfile | null {
  const match = PROFILE_MATRIX[language].find((profile) => profile.id === id);
  return match ? { ...match } : null;
}

export async function resolveCodeqlVersion(codeqlBinary: string): Promise<string> {
  try {
    const { stdout, stderr } = await execFileAsync(codeqlBinary, ["version"], {
      encoding: "utf-8",
      maxBuffer: 16 * 1024 * 1024,
      timeout: 20_000,
    });
    const output = `${stdout ?? ""}\n${stderr ?? ""}`
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find(Boolean);
    return output ?? "unknown";
  } catch (error) {
    const details = extractCommandFailure(error);
    throw new Error(
      [
        `Unable to execute CodeQL binary: ${codeqlBinary}`,
        `Run '${codeqlBinary} version' to verify the installation and binary path.`,
        details,
      ].join("\n"),
    );
  }
}

export async function detectWorkingProfile(args: DetectWorkingProfileArgs): Promise<DetectWorkingProfileResult> {
  const requestedProfile = normalizeRequestedProfile(args.codeqlApiProfile);
  const fallbackEnabled = args.codeqlProfileFallbacks ?? true;
  const validate = args.validate ?? validateProfile;
  const tried: DetectWorkingProfileResult["tried"] = [];
  const probeArgs: ProbeArgs = {
    codeqlBinary: args.codeqlBinary,
    workspaceDir: args.workspaceDir,
    probeTimeoutMs: args.probeTimeoutMs,
  };

  const candidates = resolveCandidateOrder(
    args.language,
    requestedProfile,
    fallbackEnabled,
  );

  for (const candidate of candidates) {
    try {
      await validate(candidate, probeArgs);
      tried.push({ id: candidate.id, ok: true });
      return {
        selected: candidate,
        tried,
      };
    } catch (error) {
      tried.push({
        id: candidate.id,
        ok: false,
        error: excerptError(toErrorMessage(error)),
      });
    }
  }

  throw new CodeqlProfileDetectionError(
    [
      `No compatible CodeQL API profile compiled for ${args.language}.`,
      ...tried.map((entry) => `- ${entry.id}: ${entry.error ?? "failed"}`),
    ].join("\n"),
    tried,
  );
}

export async function validateProfile(profile: CodeqlProfile, args: ProbeArgs): Promise<void> {
  const probeDir = path.join(args.workspaceDir, "exploration", "compat_probes");
  await mkdir(probeDir, { recursive: true });
  const probePath = path.join(probeDir, `${profile.id}.ql`);
  const probeQuery = renderProbeQuery(profile);
  await writeFile(probePath, probeQuery, "utf-8");

  try {
    await execFileAsync(
      args.codeqlBinary,
      ["query", "compile", probePath, "--search-path", args.workspaceDir],
      {
        cwd: args.workspaceDir,
        encoding: "utf-8",
        maxBuffer: 32 * 1024 * 1024,
        timeout: normalizeTimeout(args.probeTimeoutMs),
      },
    );
  } catch (error) {
    const details = extractCommandFailure(error);
    throw new Error(
      [
        `CodeQL profile probe failed for ${profile.id}.`,
        details,
      ].join("\n"),
    );
  }
}

export function languageBaseImport(language: TaintAnalysisLanguage): string {
  if (language === "python") return "import python";
  if (language === "go") return "import go";
  if (language === "java") return "import java";
  if (language === "csharp") return "import csharp";
  return "import javascript";
}

export function queryImportsForProfile(profile: CodeqlProfile): string {
  return [
    languageBaseImport(profile.language),
    `import ${profile.dataFlowImport}`,
    `import ${profile.taintTrackingImport}`,
  ].join("\n");
}

export function libraryImportsForProfile(profile: CodeqlProfile): string {
  return [
    languageBaseImport(profile.language),
    `import ${profile.dataFlowImport}`,
  ].join("\n");
}

export function formatProfileDiagnostics(args: {
  language: TaintAnalysisLanguage;
  codeqlVersion: string;
  requestedProfile: string;
  selectedProfileId?: string;
  fallbackEnabled: boolean;
  compatRecordPath: string;
  tried: Array<{ id: string; ok: boolean; error?: string }>;
}): string {
  const selectedLine = args.selectedProfileId
    ? [`Preflight selected profile: ${args.selectedProfileId}`]
    : [];

  return [
    "Taint-analysis CodeQL compatibility check failed.",
    `Language: ${args.language}`,
    `CodeQL version: ${args.codeqlVersion}`,
    `Requested profile: ${args.requestedProfile}`,
    ...selectedLine,
    `Profile fallbacks enabled: ${args.fallbackEnabled ? "true" : "false"}`,
    `Compatibility report: ${args.compatRecordPath}`,
    "Tried profiles:",
    ...args.tried.map((entry) => (
      `- ${entry.id}: ${entry.ok ? "ok" : `failed${entry.error ? ` (${excerptError(entry.error)})` : ""}`}`
    )),
  ].join("\n");
}

function renderProbeQuery(profile: CodeqlProfile): string {
  return [
    "/**",
    ` * @name Taint-analysis CodeQL API profile probe (${profile.id})`,
    " * @kind problem",
    ` * @id taint-analysis/compat/probe/${profile.id}`,
    " * @problem.severity recommendation",
    " */",
    "",
    languageBaseImport(profile.language),
    `import ${profile.dataFlowImport}`,
    `import ${profile.taintTrackingImport}`,
    "",
    "from DataFlow::Node n",
    "where 1 = 0",
    "select n, \"profile_probe\"",
    "",
  ].join("\n");
}

function normalizeRequestedProfile(value: "auto" | string | undefined): "auto" | string {
  if (typeof value !== "string") {
    return "auto";
  }
  const trimmed = value.trim();
  return trimmed || "auto";
}

function resolveCandidateOrder(
  language: TaintAnalysisLanguage,
  requestedProfile: "auto" | string,
  fallbackEnabled: boolean,
): CodeqlProfile[] {
  const all = candidateProfiles(language);

  if (requestedProfile !== "auto") {
    const requested = profileById(language, requestedProfile);
    if (!requested) {
      const valid = all.map((profile) => profile.id).join(", ");
      throw new Error(
        `Invalid CodeQL API profile '${requestedProfile}' for ${language}. Valid profiles: ${valid}`,
      );
    }
    return [requested];
  }

  if (!fallbackEnabled) {
    return all.slice(0, 1);
  }

  return all;
}

function normalizeTimeout(value: number | undefined): number {
  if (!Number.isFinite(value) || value == null || value <= 0) {
    return 20_000;
  }
  return Math.floor(value);
}

function extractCommandFailure(error: unknown): string {
  const err = error as ExecFileException & { stderr?: string; stdout?: string };
  const details = err.stderr?.trim() || err.stdout?.trim() || toErrorMessage(error);
  return excerptError(details);
}

function excerptError(value: string): string {
  const lines = value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (lines.length === 0) {
    return "unknown error";
  }

  return lines.slice(0, 4).join(" | ");
}

export const __taintAnalysisCodeqlCompatInternals = {
  renderProbeQuery,
  resolveCandidateOrder,
};

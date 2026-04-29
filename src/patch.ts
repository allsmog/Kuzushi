import { execFileSync, execSync } from "node:child_process";
import crypto from "node:crypto";
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import type Database from "better-sqlite3";
import { cleanupBatchFiles, writeBatchFile } from "./agent-runtime/batch-files.js";
import {
  resolveDefaultReadOnlyTools,
  runStructuredAgentQuery,
  runStructuredSessionQuery,
} from "./agent-runtime/execution.js";
import type { AgentRuntime, AgentSession } from "./agent-runtime/types.js";
import { parsePatchSynthesisOutput } from "./patch/output-parser.js";
import { DockerPocExecutor } from "./poc-executor/docker.js";
import {
  getStoredFinding,
  insertPatchResult,
  type StoredFindingRecord,
  updateFindingMetadata,
} from "./store.js";
import type { PatchResult, PatchStatus } from "./types.js";
import { normalizeCostUsd, toErrorMessage } from "./utils.js";

/* ── Public types ──────────────────────────────────────────────────────── */

export class PatchExecutionError extends Error {
  readonly costUsd: number;

  constructor(message: string, costUsd = 0) {
    super(message);
    this.name = "PatchExecutionError";
    this.costUsd = normalizeCostUsd(costUsd);
  }
}

export interface PatchSynthesisOptions {
  fingerprint: string;
  repoRoot: string;
  repoName: string;
  model: string;
  runtime: AgentRuntime;
  maxIterations: number;
  buildCommand: string | null;
  testCommand: string | null;
  /** When true, keep the worktree alive after synthesis for re-verification. Default false. */
  skipCleanup?: boolean;
}

export interface PatchPipelineResult {
  patchResult: PatchResult;
  costUsd: number;
}

/* ── Internal helpers ──────────────────────────────────────────────────── */

const PATCH_SYNTHESIS_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["diff", "explanation"],
  properties: {
    diff: { type: "string" },
    explanation: { type: "string" },
  },
} as const;

const EXEC_TIMEOUT_MS = 60_000;
const PATCH_VALIDATE_MEMORY = "1g";
const PATCH_VALIDATE_CPUS = "2";

interface PatchValidationPlan {
  build: string | null;
  test: string | null;
  dockerImage: string | null;
}

/**
 * Validate that the finding is eligible for patch synthesis.
 * Requires: finding exists, has triage data, and has confirmed exploitability.
 */
function validatePatchEligibility(db: Database.Database, fingerprint: string): StoredFindingRecord {
  const finding = getStoredFinding(db, fingerprint);
  if (!finding) {
    throw new PatchExecutionError(`Finding "${fingerprint}" not found in database.`);
  }

  if (finding.verdict == null) {
    throw new PatchExecutionError(
      `Finding "${fingerprint}" has not been triaged yet (verdict is null).`,
    );
  }

  const hasPocPass = finding.pocHarnessPath != null && finding.pocRunVerdict === "PASS";
  const hasExecutionConfirmed = finding.proofState === "execution_confirmed";

  if (!hasPocPass && !hasExecutionConfirmed) {
    throw new PatchExecutionError(
      `Finding "${fingerprint}" has no confirmed exploitability. ` +
        `Requires either a passing PoC harness (pocRunVerdict=PASS) or proofState=execution_confirmed.`,
    );
  }

  return finding;
}

/**
 * Registry of currently-active disposable worktrees.
 *
 * Patch synthesis creates a worktree at `.kuzushi/worktrees/<uuid>` per
 * finding. Normally either `runPatchPipeline` (skipCleanup=false) or the
 * patch-verify worker's finally block removes it. If the user kills the
 * process between those two points (SIGINT, SIGTERM, OOM), the worktree
 * was previously orphaned on disk and continued to count against `git
 * worktree list`. The shutdown hook below ensures we sweep them.
 */
const activeWorktrees = new Map<string, string>();

/** Forcibly remove every tracked worktree. Best-effort, swallows errors. */
export function cleanupActiveWorktreesSync(): void {
  for (const [worktreePath, repoRoot] of activeWorktrees) {
    try {
      execFileSync("git", ["worktree", "remove", "--force", worktreePath], {
        cwd: repoRoot,
        stdio: "pipe",
        timeout: EXEC_TIMEOUT_MS,
      });
    } catch {
      /* best-effort cleanup */
    }
  }
  activeWorktrees.clear();
}

/** Test/debug accessor for the active-worktree registry. */
export function __getActiveWorktreesForTest(): ReadonlyMap<string, string> {
  return activeWorktrees;
}

/**
 * Untrack a worktree from the active-worktree registry without invoking
 * `git worktree remove`. Use this from external cleanup paths that have
 * already removed the worktree themselves, so the shutdown hook doesn't
 * try to double-free it.
 */
export function untrackWorktree(worktreePath: string): void {
  activeWorktrees.delete(worktreePath);
}

/**
 * Create a disposable git worktree for safe patch application.
 */
export function createDisposableWorktree(repoRoot: string): {
  worktreePath: string;
  cleanup: () => Promise<void>;
} {
  try {
    execFileSync("git", ["rev-parse", "--is-inside-work-tree"], {
      cwd: repoRoot,
      stdio: "pipe",
      timeout: EXEC_TIMEOUT_MS,
    });
  } catch {
    throw new PatchExecutionError(`"${repoRoot}" is not inside a git repository.`);
  }

  const worktreeBase = path.join(repoRoot, ".kuzushi", "worktrees");
  mkdirSync(worktreeBase, { recursive: true });

  const uuid = crypto.randomUUID();
  const worktreePath = path.join(worktreeBase, uuid);

  execFileSync("git", ["worktree", "add", "--detach", worktreePath, "HEAD"], {
    cwd: repoRoot,
    stdio: "pipe",
    timeout: EXEC_TIMEOUT_MS,
  });
  activeWorktrees.set(worktreePath, repoRoot);

  const cleanup = async (): Promise<void> => {
    try {
      execFileSync("git", ["worktree", "remove", "--force", worktreePath], {
        cwd: repoRoot,
        stdio: "pipe",
        timeout: EXEC_TIMEOUT_MS,
      });
    } catch {
      /* best-effort cleanup */
    } finally {
      activeWorktrees.delete(worktreePath);
    }
  };

  return { worktreePath, cleanup };
}

/**
 * Detect build and test commands from common project manifest files.
 */
function detectBuildAndTestCommands(repoRoot: string): PatchValidationPlan {
  if (existsSync(path.join(repoRoot, "package.json"))) {
    return { build: "npm run build", test: "npm test", dockerImage: "node:22-slim" };
  }
  if (existsSync(path.join(repoRoot, "Makefile"))) {
    return { build: "make", test: "make test", dockerImage: "buildpack-deps:bookworm" };
  }
  if (existsSync(path.join(repoRoot, "Cargo.toml"))) {
    return { build: "cargo build", test: "cargo test", dockerImage: "rust:1.85-slim" };
  }
  if (
    existsSync(path.join(repoRoot, "setup.py")) ||
    existsSync(path.join(repoRoot, "pyproject.toml"))
  ) {
    return { build: null, test: "python -m pytest", dockerImage: "python:3.12-slim" };
  }
  if (existsSync(path.join(repoRoot, "go.mod"))) {
    return { build: "go build ./...", test: "go test ./...", dockerImage: "golang:1.22-alpine" };
  }

  return { build: null, test: null, dockerImage: null };
}

/**
 * Build the LLM prompt for patch synthesis, including previous iteration feedback.
 */
function buildPatchSynthesisPrompt(
  finding: StoredFindingRecord,
  repoName: string,
  history: Array<{ attempt: number; diff: string; status: PatchStatus; output: string }>,
): string {
  const taintInfo = finding.taintPath
    ? `Taint path:\n${finding.taintPath.map((step, i) => `  ${i + 1}. ${step.message ?? "step"} at ${step.filePath}:${step.line}`).join("\n")}`
    : "No taint path available.";

  const historyBlock =
    history.length > 0
      ? [
          "",
          "## Previous attempts (fix the issues)",
          ...history.map(
            (h) =>
              `### Attempt ${h.attempt} — ${h.status}\nDiff:\n\`\`\`diff\n${h.diff}\n\`\`\`\nValidator output:\n${h.output}`,
          ),
        ].join("\n")
      : "";

  return [
    "You are a security patch generator.",
    "Generate a minimal unified diff that fixes the vulnerability described below.",
    "The diff must be applicable with `git apply` from the repository root.",
    "",
    "## Finding",
    `Repo: ${repoName}`,
    `File: ${finding.filePath}:${finding.startLine}`,
    `Rule: ${finding.ruleId}`,
    `Severity: ${finding.severity}`,
    `Message: ${finding.message}`,
    `Rationale: ${finding.rationale}`,
    "",
    "## Taint information",
    taintInfo,
    "",
    "## Verification context",
    finding.verifyPocDescription ? `PoC description: ${finding.verifyPocDescription}` : "",
    finding.verifyAttackVector ? `Attack vector: ${finding.verifyAttackVector}` : "",
    finding.fixPatch ? `Suggested fix direction: ${finding.fixPatch}` : "",
    "",
    "## Constraints",
    "- Produce a MINIMAL patch that fixes the vulnerability without changing unrelated code.",
    "- Preserve existing functionality and do not break tests.",
    "- Use standard unified diff format with proper file paths (a/ and b/ prefixes).",
    "- Read the vulnerable file(s) before generating the patch to ensure accuracy.",
    historyBlock,
    "",
    "## Output",
    "Return ONLY a JSON object with keys:",
    "  diff (string): the unified diff content",
    "  explanation (string): brief explanation of what the patch does and why",
  ].join("\n");
}

/**
 * Use the agent runtime to synthesize a patch diff.
 */
async function synthesizePatch(
  finding: StoredFindingRecord,
  repoRoot: string,
  repoName: string,
  model: string,
  runtime: AgentRuntime,
  history: Array<{ attempt: number; diff: string; status: PatchStatus; output: string }>,
): Promise<{ diff: string; explanation: string; costUsd: number }> {
  const prompt = buildPatchSynthesisPrompt(finding, repoName, history);

  const allowedTools = resolveDefaultReadOnlyTools(runtime);

  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    allowedTools,
    runtimeOptions: { runtime },
    systemPromptPrefix:
      "You are a security patch generator. Read the vulnerable code, then produce a minimal unified diff that fixes the vulnerability.",
    schema: PATCH_SYNTHESIS_SCHEMA,
  });

  if (executionError) {
    throw new PatchExecutionError(`Patch synthesis agent failed: ${executionError}`, costUsd);
  }

  let parsed: { diff: string; explanation: string };
  try {
    parsed = parsePatchSynthesisOutput(structuredOutput ?? resultText);
  } catch (error) {
    throw new PatchExecutionError(
      `Patch synthesis output parse failed: ${toErrorMessage(error)}`,
      costUsd,
    );
  }

  return {
    diff: parsed.diff,
    explanation: parsed.explanation,
    costUsd,
  };
}

/**
 * Synthesize a patch diff via an existing session (subprocess reuse).
 * Writes iteration context to a batch file so the session can read it.
 */
async function synthesizePatchViaSession(
  session: AgentSession,
  finding: StoredFindingRecord,
  repoRoot: string,
  repoName: string,
  runId: string,
  iteration: number,
  history: Array<{ attempt: number; diff: string; status: PatchStatus; output: string }>,
): Promise<{ diff: string; explanation: string; costUsd: number }> {
  const batchFile = writeBatchFile(repoRoot, runId, "patch-synthesis", iteration, {
    fingerprint: finding.fingerprint,
    filePath: finding.filePath,
    startLine: finding.startLine,
    ruleId: finding.ruleId,
    severity: finding.severity,
    message: finding.message,
    iteration,
    history: history.map((h) => ({
      attempt: h.attempt,
      status: h.status,
      output: h.output,
      diffLength: h.diff.length,
    })),
  });

  const prompt = [
    buildPatchSynthesisPrompt(finding, repoName, history),
    "",
    `Iteration context has been written to ${batchFile} — use Read to load it if needed.`,
  ].join("\n");

  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredSessionQuery(
    session,
    prompt,
  );

  if (executionError) {
    throw new PatchExecutionError(`Patch synthesis agent failed: ${executionError}`, costUsd);
  }

  let parsed: { diff: string; explanation: string };
  try {
    parsed = parsePatchSynthesisOutput(structuredOutput ?? resultText);
  } catch (error) {
    throw new PatchExecutionError(
      `Patch synthesis output parse failed: ${toErrorMessage(error)}`,
      costUsd,
    );
  }

  return {
    diff: parsed.diff,
    explanation: parsed.explanation,
    costUsd,
  };
}

/**
 * Validate a patch through sequential checks: apply, sandboxed build, sandboxed
 * PoC re-run, sandboxed tests.
 *
 * Uses `execSync` with `input` for `git apply` operations that require piping
 * diff content through stdin. All other subprocess calls use `execFileSync` to
 * avoid shell injection. Build and test commands run inside Docker to avoid
 * executing repository code directly on the host.
 */
async function validatePatch(
  worktreePath: string,
  diff: string,
  buildCmd: string | null,
  testCmd: string | null,
  pocArtifactPath: string | null,
  dockerImage: string | null,
): Promise<{ status: PatchStatus; output: string }> {
  const logs: string[] = [];

  // Step 1: Check if the diff can be applied (requires stdin piping via execSync)
  try {
    execSync("git apply --check", {
      cwd: worktreePath,
      stdio: ["pipe", "pipe", "pipe"],
      timeout: EXEC_TIMEOUT_MS,
      input: diff,
    });
    logs.push("git apply --check: OK");
  } catch (error) {
    const msg = toErrorMessage(error);
    logs.push(`git apply --check: FAILED — ${msg}`);
    return { status: "APPLY_FAILED", output: logs.join("\n") };
  }

  // Step 2: Apply the diff (requires stdin piping via execSync)
  try {
    execSync("git apply", {
      cwd: worktreePath,
      stdio: ["pipe", "pipe", "pipe"],
      timeout: EXEC_TIMEOUT_MS,
      input: diff,
    });
    logs.push("git apply: OK");
  } catch (error) {
    const msg = toErrorMessage(error);
    logs.push(`git apply: FAILED — ${msg}`);
    return { status: "APPLY_FAILED", output: logs.join("\n") };
  }

  const requiresSandbox =
    buildCmd != null || testCmd != null || (pocArtifactPath != null && existsSync(pocArtifactPath));
  const pocExecutor = new DockerPocExecutor(EXEC_TIMEOUT_MS);
  if (requiresSandbox && !(await pocExecutor.available())) {
    logs.push("sandbox: UNAVAILABLE — Docker is required for patch validation");
    return { status: "UNKNOWN", output: logs.join("\n") };
  }

  if ((buildCmd || testCmd) && !dockerImage) {
    logs.push("sandbox: UNSUPPORTED — no sandbox image is available for build/test validation");
    return { status: "UNKNOWN", output: logs.join("\n") };
  }

  // Step 3: Run build command if present in Docker.
  if (buildCmd && dockerImage) {
    try {
      runCommandInDocker(worktreePath, dockerImage, buildCmd);
      logs.push(`build (${buildCmd}): OK`);
    } catch (error) {
      const msg = extractCommandError(error);
      logs.push(`build (${buildCmd}): FAILED — ${msg}`);
      return { status: "BUILD_FAILED", output: logs.join("\n") };
    }
  }

  // Step 4: If PoC artifact exists, copy and execute it in Docker.
  if (pocArtifactPath && existsSync(pocArtifactPath)) {
    try {
      const pocFileName = path.basename(pocArtifactPath);
      const pocDest = path.join(worktreePath, ".kuzushi", "poc-verify", pocFileName);
      mkdirSync(path.dirname(pocDest), { recursive: true });
      copyFileSync(pocArtifactPath, pocDest);

      const ext = path.extname(pocFileName).toLowerCase();
      let language: string;
      if (ext === ".py") {
        language = "python";
      } else if (ext === ".sh") {
        language = "shell";
      } else if (ext === ".ts") {
        logs.push(
          "PoC re-run: UNSUPPORTED — TypeScript harnesses are not sandbox-runnable without transpilation",
        );
        return { status: "UNKNOWN", output: logs.join("\n") };
      } else {
        language = "javascript";
      }

      const pocResult = await pocExecutor.execute(pocDest, language, worktreePath);
      const pocOutput = [pocResult.stdout, pocResult.stderr].filter(Boolean).join("\n");

      // If the PoC script still passes (exits 0), the vulnerability is not fixed
      if (pocResult.verdict === "PASS" || pocOutput.includes("PASS")) {
        logs.push("PoC re-run: STILL VULNERABLE (PoC still passes)");
        return { status: "STILL_VULNERABLE", output: logs.join("\n") };
      }
      logs.push("PoC re-run: vulnerability appears fixed (PoC did not pass)");
    } catch (error) {
      logs.push(`PoC re-run: FAILED — ${extractCommandError(error)}`);
      return { status: "UNKNOWN", output: logs.join("\n") };
    }
  }

  // Step 5: Run test command in Docker.
  if (testCmd && dockerImage) {
    try {
      runCommandInDocker(worktreePath, dockerImage, testCmd);
      logs.push(`tests (${testCmd}): OK`);
    } catch (error) {
      const msg = extractCommandError(error);
      logs.push(`tests (${testCmd}): FAILED — ${msg}`);
      return { status: "TESTS_FAILED", output: logs.join("\n") };
    }
  }

  logs.push("All validations passed.");
  return { status: "SOUND", output: logs.join("\n") };
}

function runCommandInDocker(worktreePath: string, image: string, command: string): string {
  return execFileSync(
    "docker",
    [
      "run",
      "--rm",
      "--network=none",
      `--memory=${PATCH_VALIDATE_MEMORY}`,
      `--cpus=${PATCH_VALIDATE_CPUS}`,
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=256m",
      "-e",
      "HOME=/tmp",
      "-v",
      `${worktreePath}:/repo:rw`,
      "-w",
      "/repo",
      image,
      "sh",
      "-lc",
      command,
    ],
    {
      stdio: "pipe",
      timeout: EXEC_TIMEOUT_MS,
      encoding: "utf-8",
    },
  );
}

function extractCommandError(error: unknown): string {
  const err = error as Error & { stdout?: string | Buffer; stderr?: string | Buffer };
  const stdout = typeof err.stdout === "string" ? err.stdout : err.stdout?.toString("utf-8");
  const stderr = typeof err.stderr === "string" ? err.stderr : err.stderr?.toString("utf-8");
  return [stderr, stdout, toErrorMessage(error)]
    .map((value) => value?.trim())
    .filter(Boolean)
    .join("\n");
}

/* ── Main pipeline ─────────────────────────────────────────────────────── */

export async function runPatchPipeline(
  db: Database.Database,
  options: PatchSynthesisOptions,
): Promise<PatchPipelineResult> {
  const finding = validatePatchEligibility(db, options.fingerprint);

  // Detect or use explicit build/test commands
  const detected = detectBuildAndTestCommands(options.repoRoot);
  const buildCmd = options.buildCommand ?? detected.build;
  const testCmd = options.testCommand ?? detected.test;

  const { worktreePath, cleanup } = createDisposableWorktree(options.repoRoot);

  const patchRunId = crypto.randomUUID();
  const history: Array<{
    attempt: number;
    diff: string;
    status: PatchStatus;
    output: string;
  }> = [];

  let finalStatus: PatchStatus = "UNKNOWN";
  let finalDiff: string | null = null;
  let totalCostUsd = 0;

  const canUseSession = options.runtime.createSession != null;

  // Create a session for the iteration loop if supported — one session
  // handles all iterations for this finding, avoiding up to 10 subprocess
  // spawns.
  let session: AgentSession | null = null;
  const sessionRunId = crypto.randomUUID();

  try {
    if (canUseSession) {
      session = options.runtime.createSession!({
        cwd: options.repoRoot,
        model: options.model,
        allowedTools: resolveDefaultReadOnlyTools(options.runtime),
        permissionMode: "dontAsk",
        systemPromptPrefix:
          "You are a security patch generator. Read the vulnerable code, then produce a minimal unified diff that fixes the vulnerability.",
        outputFormat: {
          type: "json_schema",
          schema: PATCH_SYNTHESIS_SCHEMA,
        },
      });
    }

    for (let iteration = 1; iteration <= options.maxIterations; iteration++) {
      // Synthesize a patch — use session if available, otherwise spawn subprocess
      const synthesis = session
        ? await synthesizePatchViaSession(
            session,
            finding,
            options.repoRoot,
            options.repoName,
            sessionRunId,
            iteration,
            history,
          )
        : await synthesizePatch(
            finding,
            options.repoRoot,
            options.repoName,
            options.model,
            options.runtime,
            history,
          );
      totalCostUsd += synthesis.costUsd;

      // Validate the patch
      const validation = await validatePatch(
        worktreePath,
        synthesis.diff,
        buildCmd,
        testCmd,
        finding.pocHarnessPath,
        detected.dockerImage,
      );

      history.push({
        attempt: iteration,
        diff: synthesis.diff,
        status: validation.status,
        output: validation.output,
      });

      if (validation.status === "SOUND") {
        finalStatus = "SOUND";
        finalDiff = synthesis.diff;
        break;
      }

      // Reset worktree for next iteration
      try {
        execFileSync("git", ["checkout", "--", "."], {
          cwd: worktreePath,
          stdio: "pipe",
          timeout: EXEC_TIMEOUT_MS,
        });
      } catch {
        /* best-effort reset */
      }

      finalStatus = validation.status;
      finalDiff = synthesis.diff;
    }
  } finally {
    // Close session if we created one
    if (session) {
      await session.close();
      cleanupBatchFiles(options.repoRoot, sessionRunId);
    }

    if (!options.skipCleanup || finalStatus !== "SOUND") {
      await cleanup();
    }
  }

  const keepWorktree = options.skipCleanup === true && finalStatus === "SOUND";

  const patchResult: PatchResult = {
    patchRunId,
    fingerprint: options.fingerprint,
    repo: options.repoName,
    diff: finalDiff,
    status: finalStatus,
    iterations: history.length,
    buildCommand: buildCmd,
    testCommand: testCmd,
    worktreePath: keepWorktree ? worktreePath : null,
    costUsd: normalizeCostUsd(totalCostUsd),
    validatorLog: history
      .map((h) => `[Attempt ${h.attempt}] ${h.status}: ${h.output}`)
      .join("\n\n"),
    history,
  };

  // Persist results
  insertPatchResult(db, patchResult);

  const existingMeta = finding.findingMetadata ?? {};
  const existingPatchRunIds = existingMeta.patchRunIds ?? [];
  updateFindingMetadata(db, options.fingerprint, {
    latestPatchRunId: patchRunId,
    patchRunIds: [...existingPatchRunIds, patchRunId],
  });

  return {
    patchResult,
    costUsd: normalizeCostUsd(totalCostUsd),
  };
}

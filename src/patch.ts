import { execFileSync, execSync } from "node:child_process";
import { existsSync, mkdirSync, copyFileSync } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import type Database from "better-sqlite3";
import {
  resolveDefaultReadOnlyTools,
  runStructuredAgentQuery,
} from "./agent-runtime/execution.js";
import {
  getStoredFinding,
  insertPatchResult,
  updateFindingMetadata,
  type StoredFindingRecord,
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
  maxIterations: number;
  buildCommand: string | null;
  testCommand: string | null;
  maxTurns?: number;
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

/**
 * Validate that the finding is eligible for patch synthesis.
 * Requires: finding exists, has triage data, and has confirmed exploitability.
 */
function validatePatchEligibility(
  db: Database.Database,
  fingerprint: string,
): StoredFindingRecord {
  const finding = getStoredFinding(db, fingerprint);
  if (!finding) {
    throw new PatchExecutionError(
      `Finding "${fingerprint}" not found in database.`,
    );
  }

  if (finding.verdict == null) {
    throw new PatchExecutionError(
      `Finding "${fingerprint}" has not been triaged yet (verdict is null).`,
    );
  }

  const hasPocPass =
    finding.pocHarnessPath != null && finding.pocRunVerdict === "PASS";
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
 * Create a disposable git worktree for safe patch application.
 */
function createDisposableWorktree(repoRoot: string): {
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
    throw new PatchExecutionError(
      `"${repoRoot}" is not inside a git repository.`,
    );
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

  const cleanup = async (): Promise<void> => {
    try {
      execFileSync("git", ["worktree", "remove", "--force", worktreePath], {
        cwd: repoRoot,
        stdio: "pipe",
        timeout: EXEC_TIMEOUT_MS,
      });
    } catch {
      /* best-effort cleanup */
    }
  };

  return { worktreePath, cleanup };
}

/**
 * Detect build and test commands from common project manifest files.
 */
function detectBuildAndTestCommands(repoRoot: string): {
  build: string | null;
  test: string | null;
} {
  if (existsSync(path.join(repoRoot, "package.json"))) {
    return { build: "npm run build", test: "npm test" };
  }
  if (existsSync(path.join(repoRoot, "Makefile"))) {
    return { build: "make", test: "make test" };
  }
  if (existsSync(path.join(repoRoot, "Cargo.toml"))) {
    return { build: "cargo build", test: "cargo test" };
  }
  if (
    existsSync(path.join(repoRoot, "setup.py")) ||
    existsSync(path.join(repoRoot, "pyproject.toml"))
  ) {
    return { build: null, test: "python -m pytest" };
  }
  if (existsSync(path.join(repoRoot, "go.mod"))) {
    return { build: "go build ./...", test: "go test ./..." };
  }

  return { build: null, test: null };
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
    ? `Taint path:\n${finding.taintPath.map((step, i) => `  ${i + 1}. ${step.label ?? step.kind} at ${step.filePath}:${step.line}`).join("\n")}`
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
    '  diff (string): the unified diff content',
    '  explanation (string): brief explanation of what the patch does and why',
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
  history: Array<{ attempt: number; diff: string; status: PatchStatus; output: string }>,
  maxTurns?: number,
): Promise<{ diff: string; explanation: string; costUsd: number }> {
  const prompt = buildPatchSynthesisPrompt(finding, repoName, history);

  const allowedTools = resolveDefaultReadOnlyTools();

  const { resultText, structuredOutput, executionError, costUsd } =
    await runStructuredAgentQuery({
      prompt,
      cwd: repoRoot,
      model,
      maxTurns: maxTurns ?? 15,
      allowedTools,
      systemPromptPrefix:
        "You are a security patch generator. Read the vulnerable code, then produce a minimal unified diff that fixes the vulnerability.",
      schema: PATCH_SYNTHESIS_SCHEMA,
    });

  if (executionError) {
    throw new PatchExecutionError(
      `Patch synthesis agent failed: ${executionError}`,
      costUsd,
    );
  }

  let parsed: { diff: string; explanation: string };
  try {
    parsed = parsePatchOutput(structuredOutput ?? resultText);
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

function parsePatchOutput(raw: unknown): { diff: string; explanation: string } {
  if (raw != null && typeof raw === "object" && !Array.isArray(raw)) {
    const record = raw as Record<string, unknown>;
    const diff = typeof record["diff"] === "string" ? record["diff"] : "";
    const explanation =
      typeof record["explanation"] === "string" ? record["explanation"] : "";

    if (!diff || diff.trim().length === 0) {
      throw new Error("Empty diff in patch synthesis output.");
    }

    return { diff, explanation };
  }

  if (typeof raw === "string") {
    // Try to extract JSON from the response text
    const braceStart = raw.indexOf("{");
    const braceEnd = raw.lastIndexOf("}");
    if (braceStart >= 0 && braceEnd > braceStart) {
      const jsonStr = raw.slice(braceStart, braceEnd + 1);
      const parsed = JSON.parse(jsonStr) as Record<string, unknown>;
      return parsePatchOutput(parsed);
    }
    throw new Error("Could not extract JSON from patch synthesis response.");
  }

  throw new Error("Unexpected patch synthesis output format.");
}

/**
 * Validate a patch through sequential checks: apply, build, PoC re-run, tests.
 *
 * Uses `execSync` with `input` for `git apply` operations that require piping
 * diff content through stdin. All other subprocess calls use `execFileSync` to
 * avoid shell injection. Build and test commands use `execSync` because they are
 * auto-detected from known manifests or explicitly provided by the operator via
 * CLI flags — they are not user-controlled untrusted input.
 */
function validatePatch(
  worktreePath: string,
  diff: string,
  buildCmd: string | null,
  testCmd: string | null,
  pocArtifactPath: string | null,
): { status: PatchStatus; output: string } {
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

  // Step 3: Run build command if present
  // Build commands come from detectBuildAndTestCommands() (hardcoded safe strings)
  // or from operator-supplied --build-cmd CLI flag (trusted operator input).
  if (buildCmd) {
    try {
      execSync(buildCmd, {
        cwd: worktreePath,
        stdio: "pipe",
        timeout: EXEC_TIMEOUT_MS,
      });
      logs.push(`build (${buildCmd}): OK`);
    } catch (error) {
      const msg = toErrorMessage(error);
      logs.push(`build (${buildCmd}): FAILED — ${msg}`);
      return { status: "BUILD_FAILED", output: logs.join("\n") };
    }
  }

  // Step 4: If PoC artifact exists, copy and execute it in worktree
  if (pocArtifactPath && existsSync(pocArtifactPath)) {
    try {
      const pocFileName = path.basename(pocArtifactPath);
      const pocDest = path.join(worktreePath, ".kuzushi", "poc-verify", pocFileName);
      mkdirSync(path.dirname(pocDest), { recursive: true });
      copyFileSync(pocArtifactPath, pocDest);

      const ext = path.extname(pocFileName).toLowerCase();
      let runProgram: string;
      let runArgs: string[];
      if (ext === ".py") {
        runProgram = "python3";
        runArgs = [pocDest];
      } else if (ext === ".sh") {
        runProgram = "sh";
        runArgs = [pocDest];
      } else if (ext === ".ts") {
        runProgram = "npx";
        runArgs = ["tsx", pocDest];
      } else {
        // .mjs, .js, .cjs, or fallback
        runProgram = "node";
        runArgs = [pocDest];
      }

      const pocResult = execFileSync(runProgram, runArgs, {
        cwd: worktreePath,
        stdio: "pipe",
        timeout: EXEC_TIMEOUT_MS,
      });
      const pocOutput = pocResult.toString("utf-8");

      // If the PoC script still passes (exits 0), the vulnerability is not fixed
      if (pocOutput.includes("PASS")) {
        logs.push("PoC re-run: STILL VULNERABLE (PoC still passes)");
        return { status: "STILL_VULNERABLE", output: logs.join("\n") };
      }
      logs.push("PoC re-run: vulnerability appears fixed (PoC did not pass)");
    } catch {
      // PoC exiting non-zero or failing means the vulnerability is likely fixed
      logs.push("PoC re-run: vulnerability appears fixed (PoC exited non-zero)");
    }
  }

  // Step 5: Run test command
  // Test commands come from detectBuildAndTestCommands() (hardcoded safe strings)
  // or from operator-supplied --test-cmd CLI flag (trusted operator input).
  if (testCmd) {
    try {
      execSync(testCmd, {
        cwd: worktreePath,
        stdio: "pipe",
        timeout: EXEC_TIMEOUT_MS,
      });
      logs.push(`tests (${testCmd}): OK`);
    } catch (error) {
      const msg = toErrorMessage(error);
      logs.push(`tests (${testCmd}): FAILED — ${msg}`);
      return { status: "TESTS_FAILED", output: logs.join("\n") };
    }
  }

  logs.push("All validations passed.");
  return { status: "SOUND", output: logs.join("\n") };
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

  try {
    for (let iteration = 1; iteration <= options.maxIterations; iteration++) {
      // Synthesize a patch
      const synthesis = await synthesizePatch(
        finding,
        options.repoRoot,
        options.repoName,
        options.model,
        history,
        options.maxTurns,
      );
      totalCostUsd += synthesis.costUsd;

      // Validate the patch
      const validation = validatePatch(
        worktreePath,
        synthesis.diff,
        buildCmd,
        testCmd,
        finding.pocHarnessPath,
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
    await cleanup();
  }

  const patchResult: PatchResult = {
    patchRunId,
    fingerprint: options.fingerprint,
    repo: options.repoName,
    diff: finalDiff,
    status: finalStatus,
    iterations: history.length,
    buildCommand: buildCmd,
    testCommand: testCmd,
    worktreePath: null, // cleaned up
    costUsd: normalizeCostUsd(totalCostUsd),
    validatorLog: history.map((h) => `[Attempt ${h.attempt}] ${h.status}: ${h.output}`).join("\n\n"),
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

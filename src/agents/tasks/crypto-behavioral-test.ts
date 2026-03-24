import { randomUUID } from "node:crypto";
import { coerceRepoContext } from "../../repo-context.js";
import { createLogger } from "../../logger.js";
import { createPocExecutor } from "../../poc-executor/index.js";
import type { Finding, ProofState } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import { normalizeCostUsd, toErrorMessage } from "../../utils.js";
import {
  generateCryptoBehavioralHarness,
  type GenerateCryptoBehavioralHarnessOptions,
  CryptoBehavioralHarnessExecutionError,
} from "../../crypto-behavioral/harness-generator.js";
import {
  classifyVerdict,
  parseCryptoBehavioralResult,
  type ParsedCryptoBehavioralResult,
} from "../../crypto-behavioral/result-parser.js";
import type {
  CryptoBehavioralRun,
  CryptoBehavioralTestType,
  CryptoBehavioralVerdict,
} from "../../crypto-behavioral/types.js";
import { insertCryptoBehavioralRun } from "../../store/crypto-behavioral.js";
import type { AgentTask, TaskContext } from "../types.js";
import { resolveTaskModel, resolveTaskPositiveInt } from "./runtime-overrides.js";

const log = createLogger({ stage: "crypto-behavioral-test" });

const PROOF_STATE_PRECEDENCE: Record<ProofState, number> = {
  symbolic_only: 0,
  inconclusive: 1,
  execution_attempted: 2,
  execution_rejected: 3,
  execution_confirmed: 4,
};

export const cryptoBehavioralTestTask: AgentTask<unknown, Finding[]> = {
  id: "crypto-behavioral-test",
  displayName: "Crypto Behavioral Test",
  outputKind: "findings",
  dependsOn: ["secrets-crypto-detect"],

  condition(upstreamOutputs, config): boolean {
    if (config.cryptoBehavioralTestEnabled !== true) {
      return false;
    }

    return getCryptoMisuseFindings(upstreamOutputs.get("secrets-crypto-detect")).length > 0;
  },

  async run(_input, context): Promise<Finding[]> {
    const sourceFindings = getCryptoMisuseFindings(
      context.upstreamOutputs.get("secrets-crypto-detect"),
    );
    if (sourceFindings.length === 0) {
      return attachTaskOutputMeta([], { costUsd: 0 });
    }

    const maxFindings = context.config.cryptoBehavioralMaxFindings ?? 10;
    const timeoutMs = context.config.cryptoBehavioralTimeoutMs ?? 120_000;
    const budgetUsd = context.config.cryptoBehavioralPerFindingBudgetUsd ?? 1;
    const model = resolveTaskModel(context, "crypto-behavioral-test");
    const maxTurns = resolveTaskPositiveInt(
      context,
      "crypto-behavioral-test",
      "maxTurns",
      context.config.taskMaxTurns ?? 10,
    );
    const timingIterations = resolveTaskPositiveInt(
      context,
      "crypto-behavioral-test",
      "timingIterations",
      10_000,
    );
    const repoContext = coerceRepoContext(context.upstreamOutputs.get("context-gatherer"));
    const executor = await createPocExecutor(context.config.pocSandbox ?? "docker", timeoutMs);

    const updatedFindings: Finding[] = [];
    let totalCostUsd = 0;

    for (const finding of sourceFindings.slice(0, maxFindings)) {
      const testType = mapFindingToTestType(finding);
      const runId = randomUUID();
      let findingCostUsd = 0;
      let parsedResult: ParsedCryptoBehavioralResult | undefined;
      let harnessPath: string | null = null;
      let harnessLanguage: string | null = null;
      let executionExitCode: number | null = null;
      let executionVerdict: CryptoBehavioralRun["executionVerdict"];
      let executionStdout = "";
      let executionStderr = "";
      let executionDurationMs: number | null = null;
      let metadata: Record<string, unknown> = {};
      let verdict: CryptoBehavioralVerdict = "error";

      try {
        const generated = await generateCryptoBehavioralHarness(
          finding,
          testType,
          context.scanPath ?? context.repoRoot,
          context.repoName,
          model,
          maxTurns,
          {
            runtime: context.runtime,
            bus: context.bus,
            runId: context.runId,
            repoContext,
            timingIterations,
          } satisfies GenerateCryptoBehavioralHarnessOptions,
        );

        findingCostUsd += normalizeCostUsd(generated.costUsd);
        harnessPath = generated.result.scriptPath;
        harnessLanguage = generated.result.language;
        metadata = {
          skipped: generated.result.skipped,
          skipReason: generated.result.skipReason ?? undefined,
          parseError: generated.result.parseError ?? undefined,
        };

        if (generated.result.skipped) {
          verdict = "inconclusive";
        } else if (!generated.result.scriptPath || !generated.result.language || generated.result.parsed === false) {
          verdict = "error";
        } else {
          const execution = await executor.execute(
            generated.result.scriptPath,
            generated.result.language,
            context.scanPath ?? context.repoRoot,
          );
          executionExitCode = execution.exitCode;
          executionVerdict = execution.verdict;
          executionStdout = execution.stdout;
          executionStderr = execution.stderr;
          executionDurationMs = execution.durationMs;

          try {
            parsedResult = parseCryptoBehavioralResult(execution.stdout);
          } catch (error) {
            metadata["resultParseError"] = toErrorMessage(error);
          }

          verdict = classifyVerdict(
            testType,
            parsedResult,
            { exitCode: execution.exitCode, verdict: execution.verdict },
          );
        }
      } catch (error) {
        if (error instanceof CryptoBehavioralHarnessExecutionError) {
          findingCostUsd += normalizeCostUsd(error.costUsd);
        }
        executionVerdict = "ERROR";
        executionStderr = toErrorMessage(error);
        metadata = {
          ...metadata,
          error: toErrorMessage(error),
        };
        verdict = "error";
        log.warn(`[crypto-behavioral-test] ${finding.fingerprint}: ${toErrorMessage(error)}`);
      }

      totalCostUsd += findingCostUsd;

      const enrichedFinding = enrichFinding(
        finding,
        testType,
        verdict,
        parsedResult,
        executionExitCode,
        executionVerdict,
        executionStderr || executionStdout || undefined,
      );
      updatedFindings.push(enrichedFinding);

      if (context.db) {
        const run: CryptoBehavioralRun = {
          runId,
          pipelineRunId: context.runId,
          fingerprint: finding.fingerprint,
          repo: context.repoName,
          testType,
          verdict,
          harnessPath,
          harnessLanguage,
          executionExitCode,
          executionVerdict,
          executionStdout: executionStdout || undefined,
          executionStderr: executionStderr || undefined,
          executionDurationMs,
          tStatistic: parsedResult?.timing?.tStatistic ?? null,
          pValue: parsedResult?.timing?.pValue ?? null,
          meanANs: parsedResult?.timing?.meanANs ?? null,
          meanBNs: parsedResult?.timing?.meanBNs ?? null,
          timingIterations: parsedResult?.timing?.iterations ?? null,
          observedBehavior: parsedResult?.result.observedBehavior,
          expectedBehavior: parsedResult?.result.expectedBehavior,
          algorithmConfirmed: parsedResult?.result.algorithmConfirmed,
          keyLengthBits: parsedResult?.result.keyLengthBits ?? null,
          costUsd: findingCostUsd,
          metadata,
        };
        insertCryptoBehavioralRun(context.db, run);
      }

      if (findingCostUsd >= budgetUsd) {
        log.info(
          `[crypto-behavioral-test] budget reached after ${finding.fingerprint}: $${findingCostUsd.toFixed(4)} >= $${budgetUsd.toFixed(4)}`,
        );
        break;
      }
    }

    return attachTaskOutputMeta(updatedFindings, { costUsd: totalCostUsd });
  },
};

function getCryptoMisuseFindings(value: unknown): Finding[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item): item is Finding =>
    Boolean(item)
    && typeof item === "object"
    && typeof (item as Finding).ruleId === "string"
    && (item as Finding).ruleId.startsWith("crypto-misuse/"),
  );
}

function mapFindingToTestType(finding: Finding): CryptoBehavioralTestType {
  const category = finding.ruleId.replace(/^crypto-misuse\//, "");

  switch (category) {
    case "timing-attack":
      return "timing";
    case "ecb-mode":
      return "ecb-mode";
    case "hash-for-auth":
    case "password-storage":
      return "weak-hash";
    case "insecure-prng":
    case "key-generation":
      return "weak-prng";
    case "key-length":
      return "key-length";
    case "symmetric-cipher":
      return /ecb/i.test(`${finding.message} ${finding.evidence ?? ""}`) ? "ecb-mode" : "edge-case";
    case "tls-config":
    case "cert-validation":
      return "edge-case";
    default:
      return "edge-case";
  }
}

function enrichFinding(
  finding: Finding,
  testType: CryptoBehavioralTestType,
  verdict: CryptoBehavioralVerdict,
  parsed: ParsedCryptoBehavioralResult | undefined,
  executionExitCode: number | null,
  executionVerdict: CryptoBehavioralRun["executionVerdict"],
  detailFallback: string | undefined,
): Finding {
  const nextProofState = proofStateForVerdict(verdict);
  const detail = buildProvenanceDetail(testType, verdict, parsed, executionExitCode, executionVerdict, detailFallback);

  return {
    ...finding,
    proofState: mergeProofState(finding.proofState, nextProofState),
    engineProvenance: appendEngineProvenance(
      finding.engineProvenance,
      { kind: "dynamic", detail },
    ),
  };
}

function proofStateForVerdict(verdict: CryptoBehavioralVerdict): ProofState {
  switch (verdict) {
    case "vulnerable":
      return "execution_confirmed";
    case "secure":
      return "execution_rejected";
    case "inconclusive":
    case "error":
      return "execution_attempted";
  }
}

function mergeProofState(
  existing: ProofState | undefined,
  next: ProofState,
): ProofState {
  if (!existing) {
    return next;
  }

  return PROOF_STATE_PRECEDENCE[next] > PROOF_STATE_PRECEDENCE[existing]
    ? next
    : existing;
}

function appendEngineProvenance(
  existing: Finding["engineProvenance"],
  next: NonNullable<Finding["engineProvenance"]>[number],
): NonNullable<Finding["engineProvenance"]> {
  const current = existing ? [...existing] : [];
  if (!current.some((entry) => entry.kind === next.kind && entry.detail === next.detail)) {
    current.push(next);
  }
  return current;
}

function buildProvenanceDetail(
  testType: CryptoBehavioralTestType,
  verdict: CryptoBehavioralVerdict,
  parsed: ParsedCryptoBehavioralResult | undefined,
  executionExitCode: number | null,
  executionVerdict: CryptoBehavioralRun["executionVerdict"],
  detailFallback: string | undefined,
): string {
  const parts = [
    `crypto-behavioral/${testType}`,
    `verdict=${verdict}`,
  ];

  if (parsed?.timing) {
    parts.push(
      `t=${formatNumber(parsed.timing.tStatistic)}`,
      `p=${formatNumber(parsed.timing.pValue)}`,
      `iterations=${formatInteger(parsed.timing.iterations)}`,
    );
  }

  if (parsed?.result.algorithmConfirmed) {
    parts.push(`algorithm=${sanitizeDetail(parsed.result.algorithmConfirmed)}`);
  }

  if (parsed?.result.keyLengthBits != null) {
    parts.push(`keyBits=${parsed.result.keyLengthBits}`);
  }

  if (parsed?.result.observedBehavior) {
    parts.push(`observed=${sanitizeDetail(parsed.result.observedBehavior)}`);
  }

  if (parsed?.result.expectedBehavior) {
    parts.push(`expected=${sanitizeDetail(parsed.result.expectedBehavior)}`);
  }

  if (executionVerdict) {
    parts.push(`exec=${executionVerdict}`);
  }

  if (executionExitCode != null) {
    parts.push(`exit=${executionExitCode}`);
  }

  if (parts.length <= 2 && detailFallback) {
    parts.push(`detail=${sanitizeDetail(detailFallback)}`);
  }

  return parts.join(" ");
}

function formatNumber(value: number | null | undefined): string {
  return typeof value === "number" && Number.isFinite(value)
    ? value.toFixed(4)
    : "n/a";
}

function formatInteger(value: number | null | undefined): string {
  return typeof value === "number" && Number.isFinite(value)
    ? String(Math.floor(value))
    : "n/a";
}

function sanitizeDetail(value: string): string {
  return value.replace(/\s+/g, " ").trim().slice(0, 120);
}

export const __cryptoBehavioralTestInternals = {
  getCryptoMisuseFindings,
  mapFindingToTestType,
  proofStateForVerdict,
  mergeProofState,
  buildProvenanceDetail,
};

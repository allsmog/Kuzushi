/**
 * Zod schemas for runtime validation at system boundaries.
 *
 * These schemas are the source of truth for core data shapes.
 * TypeScript types are derived via `z.infer<>` and re-exported
 * from their original modules so that existing imports keep working.
 */
import { z } from "zod";

// ---------------------------------------------------------------------------
// Shared enums / literals
// ---------------------------------------------------------------------------

export const VerdictSchema = z.enum(["tp", "fp", "needs_review"]);

export const BusBackendSchema = z.enum([
  "in-process",
  "redis",
  "google-pubsub",
  "nats",
]);

export const ScanModeSchema = z.enum(["sequential", "concurrent"]);

export const AgentRuntimeBackendSchema = z.enum(["pi-ai", "acp"]);

export const ProofVerdictSchema = z.enum([
  "exploited",
  "blocked_by_security",
  "out_of_scope",
  "false_positive",
]);

export const PocExecVerdictSchema = z.enum(["PASS", "FAIL", "ERROR", "TIMEOUT"]);

export const PocSandboxSchema = z.enum(["docker", "process"]);

export const TriageStrategySchema = z.enum(["single", "multi-agent"]);

export const DataSensitivitySchema = z.enum([
  "public",
  "internal",
  "confidential",
  "restricted",
]);

export const ExploitChainSeveritySchema = z.enum(["CRITICAL", "HIGH", "MEDIUM"]);

// ---------------------------------------------------------------------------
// Finding (scanner output)
// ---------------------------------------------------------------------------

export const FindingSchema = z.object({
  scanner: z.string(),
  fingerprint: z.string(),
  ruleId: z.string(),
  filePath: z.string(),
  startLine: z.number(),
  severity: z.string(),
  message: z.string(),
  evidence: z.string().nullable().optional(),
  scannerConfidence: z.string(),
  subcategory: z.array(z.string()),
  likelihood: z.string(),
  impact: z.string(),
  cwe: z.array(z.string()),
  score: z.number(),
  adjustedScore: z.number().optional(),
  corroboratingSignals: z.array(
    z.object({
      scanner: z.string(),
      fingerprint: z.string(),
      ruleId: z.string(),
      filePath: z.string(),
      startLine: z.number(),
      cwe: z.array(z.string()),
      score: z.number(),
    }),
  ).optional(),
  suppressionReasons: z.array(
    z.object({
      id: z.string(),
      kind: z.enum(["hard", "soft"]),
      description: z.string(),
      scorePenalty: z.number().optional(),
    }),
  ).optional(),
});

export type FindingZ = z.infer<typeof FindingSchema>;

// ---------------------------------------------------------------------------
// Triage types
// ---------------------------------------------------------------------------

export const TriagePathAssessmentSchema = z.object({
  why: z.string(),
  isFalsePositive: z.boolean(),
  evidence: z.string(),
});

export type TriagePathAssessmentZ = z.infer<typeof TriagePathAssessmentSchema>;

export const EvidenceStepSchema = z.object({
  stepType: z.string(),
  description: z.string(),
  confidence: z.number(),
  evidence: z.string(),
});

export type EvidenceStepZ = z.infer<typeof EvidenceStepSchema>;

export const TriageResultSchema = z.object({
  fingerprint: z.string(),
  verdict: VerdictSchema,
  confidence: z.number(),
  rationale: z.string(),
  verificationSteps: z.array(z.string()),
  fixPatch: z.string().nullable(),
  source: TriagePathAssessmentSchema.optional(),
  sink: TriagePathAssessmentSchema.optional(),
  isVulnerable: z.boolean().optional(),
  exploitScenario: z.string().optional(),
  recommendedFix: z.string().optional(),
  ruleRefinementHint: z.string().optional(),
  triageSchemaVersion: z.string().optional(),
  evidenceTrail: z
    .array(z.object({ level: z.string(), evidence: z.string() }))
    .optional(),
  triageCostUsd: z.number().optional(),
  calibratedConfidence: z.number().optional(),
  evidenceChain: z.array(EvidenceStepSchema).optional(),
});

export type TriageResultZ = z.infer<typeof TriageResultSchema>;

// ---------------------------------------------------------------------------
// Verification types
// ---------------------------------------------------------------------------

export const VerificationResultSchema = z.object({
  fingerprint: z.string(),
  exploitable: z.boolean(),
  pocPayload: z.string().nullable(),
  pocDescription: z.string(),
  attackVector: z.string().nullable(),
  preconditions: z.array(z.string()),
  confidence: z.number(),
  proofLevel: z.union([z.literal(1), z.literal(2), z.literal(3), z.literal(4)]).optional(),
  proofVerdict: ProofVerdictSchema.optional(),
  bypassAttempts: z.array(z.string()).optional(),
  verifyCostUsd: z.number().optional(),
});

export type VerificationResultZ = z.infer<typeof VerificationResultSchema>;

// ---------------------------------------------------------------------------
// PoC Harness types
// ---------------------------------------------------------------------------

export const PocHarnessResultSchema = z.object({
  fingerprint: z.string(),
  scriptPath: z.string().nullable(),
  language: z.string().nullable(),
  scriptContent: z.string().nullable(),
  parsed: z.boolean(),
  parseError: z.string().nullable(),
  skipped: z.boolean(),
  skipReason: z.string().nullable(),
  costUsd: z.number().optional(),
  pocExecExitCode: z.number().optional(),
  pocExecStdout: z.string().optional(),
  pocExecStderr: z.string().optional(),
  pocExecVerdict: PocExecVerdictSchema.optional(),
  pocExecDurationMs: z.number().optional(),
});

export type PocHarnessResultZ = z.infer<typeof PocHarnessResultSchema>;

// ---------------------------------------------------------------------------
// Repo context types
// ---------------------------------------------------------------------------

export const RepoContextSchema = z.object({
  languages: z.array(z.string()),
  frameworks: z.array(z.string()),
  authPatterns: z.array(z.string()),
  sanitizationLibs: z.array(z.string()),
  ormOrDb: z.array(z.string()),
  entryPoints: z.array(z.string()),
});

export type RepoContextZ = z.infer<typeof RepoContextSchema>;

export const EnrichedRepoContextSchema = z.object({
  base: RepoContextSchema,
  enrichment: z.object({
    customMiddleware: z.array(
      z.object({
        name: z.string(),
        filePath: z.string(),
        purpose: z.string(),
        appliesTo: z.string().optional(),
      }),
    ),
    customSanitizers: z.array(
      z.object({
        name: z.string(),
        filePath: z.string(),
        sanitizationType: z.string(),
        usedBy: z.string().optional(),
      }),
    ),
    trustBoundaries: z.array(
      z.object({
        name: z.string(),
        description: z.string(),
        entryPoints: z.array(z.string()).optional(),
      }),
    ),
    dataClassifications: z.array(
      z.object({
        dataType: z.string(),
        sensitivity: DataSensitivitySchema,
        locations: z.array(z.string()).optional(),
      }),
    ),
    architecturalNotes: z.array(z.string()),
  }),
});

export type EnrichedRepoContextZ = z.infer<typeof EnrichedRepoContextSchema>;

// ---------------------------------------------------------------------------
// Precedents & security profiles
// ---------------------------------------------------------------------------

export const PrecedentsSchema = z.object({
  hardExclusions: z.array(z.string()),
  signalCriteria: z.array(z.string()),
  architecturalPrecedents: z.array(z.string()),
});

export type PrecedentsZ = z.infer<typeof PrecedentsSchema>;

export const SecurityProfileSchema = z.object({
  name: z.string(),
  items: z.array(z.string()),
  appliesTo: z.array(z.string()).optional(),
});

export type SecurityProfileZ = z.infer<typeof SecurityProfileSchema>;

// ---------------------------------------------------------------------------
// Exploit chains
// ---------------------------------------------------------------------------

export const ExploitChainSchema = z.object({
  id: z.string(),
  name: z.string(),
  steps: z.array(
    z.object({
      findingFingerprint: z.string(),
      role: z.string(),
      description: z.string(),
    }),
  ),
  overallSeverity: ExploitChainSeveritySchema,
  preconditions: z.array(z.string()),
  impactDescription: z.string(),
});

export type ExploitChainZ = z.infer<typeof ExploitChainSchema>;

// ---------------------------------------------------------------------------
// ScanOpts
// ---------------------------------------------------------------------------

export const ScanOptsSchema = z.object({
  severity: z.array(z.string()),
  maxFindings: z.number().optional(),
  excludePatterns: z.array(z.string()),
  scanners: z.array(z.string()).optional(),
  fresh: z.boolean(),
  diffBase: z.string().optional(),
  agenticReviewContext: z.string().optional(),
});

export type ScanOptsZ = z.infer<typeof ScanOptsSchema>;

// ---------------------------------------------------------------------------
// Agent runtime config
// ---------------------------------------------------------------------------

export const AgentRuntimeConfigSchema = z.object({
  apiKey: z.string().optional(),
  baseUrl: z.string().optional(),
});

export type AgentRuntimeConfigZ = z.infer<typeof AgentRuntimeConfigSchema>;

// ---------------------------------------------------------------------------
// KuzushiConfig — the full configuration object
// ---------------------------------------------------------------------------

export const KuzushiConfigSchema = z.object({
  model: z.string(),
  triageModel: z.string().optional(),
  triageMaxTurns: z.number().nullable(),
  verify: z.boolean().optional(),
  verifyModel: z.string().optional(),
  verifyMaxTurns: z.number().optional(),
  verifyConcurrency: z.number().optional(),
  verifyBatchSize: z.number().optional(),
  verifyVerdicts: z.array(VerdictSchema).optional(),
  verifyMinConfidence: z.number().optional(),
  pocHarness: z.boolean().optional(),
  pocHarnessModel: z.string().optional(),
  pocHarnessMaxTurns: z.number().optional(),
  pocHarnessConcurrency: z.number().optional(),
  enableContextGathering: z.boolean().optional(),
  auditLog: z.boolean().optional(),
  reportOutput: z.string().optional(),
  sarifOutput: z.string().optional(),
  maxTriageRetries: z.number().optional(),
  maxVerifyRetries: z.number().optional(),
  maxPocHarnessRetries: z.number().optional(),
  retryBackoffMs: z.number().optional(),
  retryBackoffMultiplier: z.number().optional(),
  busBackend: BusBackendSchema,
  triageBatchSize: z.number(),
  triageConcurrency: z.number(),
  scanMode: ScanModeSchema,
  agentRuntimeBackend: AgentRuntimeBackendSchema.optional(),
  agentRuntimeConfig: AgentRuntimeConfigSchema.optional(),
  enabledTasks: z.array(z.string()).optional(),
  scanners: z.array(z.string()),
  severity: z.array(z.string()),
  excludePatterns: z.array(z.string()),
  scannerConfig: z.record(z.string(), z.record(z.string(), z.unknown())),
  fpFilterEnabled: z.boolean().optional(),
  fpFilterCustomExclusions: z.array(z.string()).optional(),
  variantAnalysis: z.boolean().optional(),
  variantAnalysisModel: z.string().optional(),
  variantAnalysisMaxFindings: z.number().optional(),
  enableContextEnrichment: z.boolean().optional(),
  contextEnrichmentModel: z.string().optional(),
  diffBase: z.string().optional(),
  llmRescoreEnabled: z.boolean().optional(),
  llmRescoreModel: z.string().optional(),
  llmRescoreThreshold: z.number().optional(),
  chainAnalysis: z.boolean().optional(),
  chainAnalysisModel: z.string().optional(),
  precedentsPath: z.string().optional(),
  securityProfilesPath: z.string().optional(),
  prioritizeFindings: z.boolean().optional(),
  costBudgetUsd: z.number().optional(),
  enableDynamicTaskSelection: z.boolean().optional(),
  pocExecute: z.boolean().optional(),
  pocSandbox: PocSandboxSchema.optional(),
  pocExecTimeoutMs: z.number().optional(),
  confidenceCalibration: z.boolean().optional(),
  confidenceSignalWeights: z.object({
    scanner: z.number().optional(),
    triage: z.number().optional(),
    verification: z.number().optional(),
    history: z.number().optional(),
    context: z.number().optional(),
  }).optional(),
  trajectoryMemory: z.boolean().optional(),
  trajectoryMaxExemplars: z.number().optional(),
  triageStrategy: TriageStrategySchema.optional(),
  triageSpecialistModel: z.string().optional(),
  triageSpecialistMaxTurns: z.number().nullable().optional(),
  triageAssertions: z.object({
    enabled: z.boolean().optional(),
    weights: z.object({
      rationaleHasEvidence: z.number().optional(),
      verificationStepsActionable: z.number().optional(),
      confidenceMatchesEvidence: z.number().optional(),
      noEmptyRationale: z.number().optional(),
      cweMentionsRelevant: z.number().optional(),
      fixPatchValid: z.number().optional(),
      severityVerdictAlignment: z.number().optional(),
      verdictConsistency: z.number().optional(),
      costEfficiency: z.number().optional(),
      latencyReasonable: z.number().optional(),
    }).optional(),
  }).optional(),
  qualityGates: z.object({
    failOnHighSeverityTP: z.boolean().optional(),
    maxOpenFindings: z.number().optional(),
    minTriageConfidence: z.number().optional(),
    failOnExploitable: z.boolean().optional(),
  }).optional(),
  jsonOutput: z.string().optional(),
  csvOutput: z.string().optional(),
  jsonlOutput: z.string().optional(),
  externalTasks: z.array(z.string()).optional(),
  enableExternalTasks: z.boolean().optional(),
  hooks: z.object({
    files: z.array(z.string()).optional(),
  }).optional(),
  enableExternalHooks: z.boolean().optional(),
  triagePromptFile: z.string().optional(),
  verifyPromptFile: z.string().optional(),
  acpAdapterCommand: z.string().optional(),
  acpSessionPersist: z.boolean().optional(),
  bootstrapFiles: z.object({
    files: z.array(z.string()).optional(),
    maxCharsPerFile: z.number().optional(),
    totalMaxChars: z.number().optional(),
  }).optional(),
  toolPolicies: z.record(z.string(), z.object({
    allow: z.array(z.string()).optional(),
    deny: z.array(z.string()).optional(),
  })).optional(),
  incrementalCache: z.boolean().optional(),
});

export type KuzushiConfigZ = z.infer<typeof KuzushiConfigSchema>;

// ---------------------------------------------------------------------------
// FindingRow (SQLite persistence)
// ---------------------------------------------------------------------------

export const FindingRowSchema = z.object({
  scanner: z.string(),
  fingerprint: z.string(),
  repo: z.string(),
  ref: z.string(),
  ruleId: z.string(),
  filePath: z.string(),
  startLine: z.number(),
  severity: z.string(),
  message: z.string(),
  verdict: VerdictSchema,
  confidence: z.number(),
  rationale: z.string(),
  verificationSteps: z.string(),
  fixPatch: z.string().nullable(),
  triageDetailsJson: z.string().nullable().optional(),
  verifyExploitable: z.number().nullable().optional(),
  verifyPocPayload: z.string().nullable().optional(),
  verifyPocDescription: z.string().nullable().optional(),
  verifyAttackVector: z.string().nullable().optional(),
  verifyPreconditions: z.string().nullable().optional(),
  verifyConfidence: z.number().nullable().optional(),
  verifyCostUsd: z.number().nullable().optional(),
  pocHarnessPath: z.string().nullable().optional(),
  pocHarnessLanguage: z.string().nullable().optional(),
  pocHarnessParsed: z.number().nullable().optional(),
  pocHarnessParseError: z.string().nullable().optional(),
  pocHarnessSkipped: z.number().nullable().optional(),
  pocHarnessSkipReason: z.string().nullable().optional(),
  pocHarnessCostUsd: z.number().nullable().optional(),
  compositeConfidence: z.number().nullable().optional(),
  confidenceSignalsJson: z.string().nullable().optional(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

export type FindingRowZ = z.infer<typeof FindingRowSchema>;

// ---------------------------------------------------------------------------
// LLM output schemas (snake_case — used to validate raw LLM JSON)
// ---------------------------------------------------------------------------

/**
 * Schema for raw triage agent LLM output (snake_case keys).
 * This validates the JSON coming from the LLM before it is normalized
 * into the camelCase TriageResult.
 */
export const RawTriageOutputSchema = z.object({
  fingerprint: z.string(),
  verdict: VerdictSchema,
  confidence: z.number(),
  rationale: z.string(),
  verification_steps: z.array(z.string()).min(1),
  fix_patch: z.string().nullable().optional(),
  source: z
    .object({
      why: z.string(),
      is_false_positive: z.boolean(),
      evidence: z.string(),
    })
    .optional(),
  sink: z
    .object({
      why: z.string(),
      is_false_positive: z.boolean(),
      evidence: z.string(),
    })
    .optional(),
  is_vulnerable: z.boolean().optional(),
  exploit_scenario: z.string().optional(),
  recommended_fix: z.string().optional(),
  rule_refinement_hint: z.string().optional(),
  triage_schema_version: z.string().optional(),
  evidence_trail: z
    .array(z.object({ level: z.string(), evidence: z.string() }))
    .optional(),
  evidence_chain: z
    .array(
      z.object({
        step_type: z.string(),
        description: z.string(),
        confidence: z.number(),
        evidence: z.string(),
      }),
    )
    .optional(),
});

export type RawTriageOutput = z.infer<typeof RawTriageOutputSchema>;

/**
 * Schema for raw verification agent LLM output (snake_case keys).
 */
export const RawVerificationOutputSchema = z.object({
  fingerprint: z.string(),
  exploitable: z.boolean(),
  poc_payload: z.string().nullable(),
  poc_description: z.string(),
  attack_vector: z.string().nullable(),
  preconditions: z.array(z.string()),
  confidence: z.number(),
  proof_level: z.number().int().min(1).max(4).optional(),
  proof_verdict: z.string().optional(),
  bypass_attempts: z.array(z.string()).optional(),
});

export type RawVerificationOutput = z.infer<typeof RawVerificationOutputSchema>;

/**
 * Batch wrapper for triage results.
 */
export const RawBatchTriageOutputSchema = z.object({
  results: z.array(RawTriageOutputSchema),
});

/**
 * Batch wrapper for verification results.
 */
export const RawBatchVerificationOutputSchema = z.object({
  results: z.array(RawVerificationOutputSchema),
});

/**
 * Schema for raw PoC harness agent LLM output (snake_case keys).
 */
export const RawPocHarnessOutputSchema = z.object({
  fingerprint: z.string(),
  script_content: z.string().nullable(),
  language: z.string().nullable(),
  skipped: z.boolean(),
  skip_reason: z.string().nullable().optional(),
});

export type RawPocHarnessOutput = z.infer<typeof RawPocHarnessOutputSchema>;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

export interface ValidationError {
  path: string;
  message: string;
}

/**
 * Format Zod issues into human-readable validation error details.
 */
export function formatZodErrors(issues: z.ZodIssue[]): ValidationError[] {
  return issues.map((issue) => ({
    path: issue.path.join(".") || "<root>",
    message: issue.message,
  }));
}

/**
 * Format validation errors into a single human-readable string.
 */
export function formatValidationErrorMessage(
  label: string,
  errors: ValidationError[],
): string {
  const details = errors
    .map((e) => `  - ${e.path}: ${e.message}`)
    .join("\n");
  return `${label} validation failed:\n${details}`;
}

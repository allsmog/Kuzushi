/**
 * Zod schemas for runtime validation at system boundaries.
 *
 * These schemas are the source of truth for core data shapes.
 * TypeScript types are derived via `z.infer<>` and re-exported
 * from their original modules so that existing imports keep working.
 */
import { z } from "zod";
import {
  AGENT_RUNTIME_BACKENDS,
  BUS_BACKENDS,
  DATA_SENSITIVITIES,
  DISPLAY_SEVERITIES,
  DYNAMIC_ANALYSIS_STATUSES,
  DYNAMIC_COVERAGE_MODES,
  ENGINE_PROVENANCE_KINDS,
  EXPLOIT_CHAIN_SEVERITIES,
  PATCH_STATUSES,
  POC_EXECUTION_VERDICTS,
  POC_SANDBOX_BACKENDS,
  PROOF_STATES,
  PROOF_VERDICTS,
  SCAN_MODES,
  TRIAGE_STRATEGIES,
  VERDICTS,
} from "./contracts.js";

// ---------------------------------------------------------------------------
// Shared enums / literals
// ---------------------------------------------------------------------------

export const VerdictSchema = z.enum(VERDICTS);
export type VerdictZ = z.infer<typeof VerdictSchema>;

export const DisplaySeveritySchema = z.enum(DISPLAY_SEVERITIES);
export type DisplaySeverityZ = z.infer<typeof DisplaySeveritySchema>;

export const BusBackendSchema = z.enum(BUS_BACKENDS);
export type BusBackendZ = z.infer<typeof BusBackendSchema>;

export const ScanModeSchema = z.enum(SCAN_MODES);
export type ScanModeZ = z.infer<typeof ScanModeSchema>;

export const AgentRuntimeBackendSchema = z.enum(AGENT_RUNTIME_BACKENDS);
export type AgentRuntimeBackendZ = z.infer<typeof AgentRuntimeBackendSchema>;

export const ProofVerdictSchema = z.enum(PROOF_VERDICTS);
export type ProofVerdictZ = z.infer<typeof ProofVerdictSchema>;

export const PocExecVerdictSchema = z.enum(POC_EXECUTION_VERDICTS);
export type PocExecVerdictZ = z.infer<typeof PocExecVerdictSchema>;

export const PocSandboxSchema = z.enum(POC_SANDBOX_BACKENDS);
export type PocSandboxZ = z.infer<typeof PocSandboxSchema>;

export const TriageStrategySchema = z.enum(TRIAGE_STRATEGIES);
export type TriageStrategyZ = z.infer<typeof TriageStrategySchema>;

export const DataSensitivitySchema = z.enum(DATA_SENSITIVITIES);
export type DataSensitivityZ = z.infer<typeof DataSensitivitySchema>;

export const ExploitChainSeveritySchema = z.enum(EXPLOIT_CHAIN_SEVERITIES);
export type ExploitChainSeverityZ = z.infer<typeof ExploitChainSeveritySchema>;
export const ProofStateSchema = z.enum(PROOF_STATES);
export type ProofStateZ = z.infer<typeof ProofStateSchema>;
export const DynamicAnalysisStatusSchema = z.enum(DYNAMIC_ANALYSIS_STATUSES);
export type DynamicAnalysisStatusZ = z.infer<typeof DynamicAnalysisStatusSchema>;
export const DynamicCoverageModeSchema = z.enum(DYNAMIC_COVERAGE_MODES);
export type DynamicCoverageModeZ = z.infer<typeof DynamicCoverageModeSchema>;
export const PatchStatusSchema = z.enum(PATCH_STATUSES);
export type PatchStatusZ = z.infer<typeof PatchStatusSchema>;

// ---------------------------------------------------------------------------
// Finding (task output)
// ---------------------------------------------------------------------------

export const TaintPathStepSchema = z.object({
  filePath: z.string(),
  line: z.number(),
  message: z.string().optional(),
  snippet: z.string().optional(),
});

export const EngineProvenanceSchema = z.object({
  kind: z.enum(ENGINE_PROVENANCE_KINDS),
  detail: z.string(),
});

export const FindingSchema = z.object({
  taskId: z.string(),
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
  taintPath: z.array(TaintPathStepSchema).optional(),
  proofState: ProofStateSchema.optional(),
  engineProvenance: z.array(EngineProvenanceSchema).optional(),
  corroboratingSignals: z
    .array(
      z.object({
        taskId: z.string(),
        fingerprint: z.string(),
        ruleId: z.string(),
        filePath: z.string(),
        startLine: z.number(),
        cwe: z.array(z.string()),
        score: z.number(),
      }),
    )
    .optional(),
  suppressionReasons: z
    .array(
      z.object({
        id: z.string(),
        kind: z.enum(["hard", "soft"]),
        description: z.string(),
        scorePenalty: z.number().optional(),
      }),
    )
    .optional(),
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

export const CodeCitationSchema = z.object({
  filePath: z.string(),
  startLine: z.number(),
  endLine: z.number(),
  snippet: z.string(),
  description: z.string(),
});

export type CodeCitationZ = z.infer<typeof CodeCitationSchema>;

export const AttackPathAnalysisSchema = z.object({
  chain: z.array(z.string()),
  narrative: z.string(),
  likelihoodReasoning: z.string(),
  impactReasoning: z.string(),
});

export type AttackPathAnalysisZ = z.infer<typeof AttackPathAnalysisSchema>;

export const SecurityControlSchema = z.object({
  name: z.string(),
  description: z.string(),
  filePath: z.string().optional(),
});

export type SecurityControlZ = z.infer<typeof SecurityControlSchema>;

export const TriageResultSchema = z.object({
  fingerprint: z.string(),
  title: z.string().optional(),
  attackNarrative: z.string().optional(),
  displaySeverity: DisplaySeveritySchema.optional(),
  verdict: VerdictSchema,
  confidence: z.number(),
  rationale: z.string(),
  verificationSteps: z.array(z.string()),
  fixPatch: z.string().nullable(),
  source: TriagePathAssessmentSchema.optional(),
  sink: TriagePathAssessmentSchema.optional(),
  sinkFunction: z.string().nullable().optional(),
  isVulnerable: z.boolean().optional(),
  exploitScenario: z.string().optional(),
  recommendedFix: z.string().optional(),
  ruleRefinementHint: z.string().optional(),
  triageSchemaVersion: z.string().optional(),
  evidenceTrail: z.array(z.object({ level: z.string(), evidence: z.string() })).optional(),
  triageCostUsd: z.number().optional(),
  calibratedConfidence: z.number().optional(),
  compositeConfidence: z.number().optional(),
  evidenceChain: z.array(EvidenceStepSchema).optional(),
  codeCitations: z.array(CodeCitationSchema).optional(),
  attackPath: AttackPathAnalysisSchema.optional(),
  assumptions: z.array(z.string()).optional(),
  controls: z.array(SecurityControlSchema).optional(),
  blindspots: z.array(z.string()).optional(),
  sourceThreatIds: z.array(z.string()).optional(),
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
  compositeConfidence: z.number().optional(),
  codeCitations: z.array(CodeCitationSchema).optional(),
  attackPath: AttackPathAnalysisSchema.optional(),
  assumptions: z.array(z.string()).optional(),
  controls: z.array(SecurityControlSchema).optional(),
  blindspots: z.array(z.string()).optional(),
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
  iterations: z.number().optional(),
  refinementHistory: z
    .array(
      z.object({
        attempt: z.number(),
        error: z.string(),
        approach: z.string(),
      }),
    )
    .optional(),
});

export type PocHarnessResultZ = z.infer<typeof PocHarnessResultSchema>;

export const DynamicAnalysisRunSchema = z.object({
  dynamicRunId: z.string(),
  pipelineRunId: z.string().optional(),
  fingerprint: z.string(),
  repo: z.string(),
  status: DynamicAnalysisStatusSchema,
  score: z.number(),
  proofValue: z.number(),
  language: z.string().optional(),
  harnessPath: z.string().nullable().optional(),
  harnessLanguage: z.string().nullable().optional(),
  seedInputs: z.array(z.string()).optional(),
  coverageMode: DynamicCoverageModeSchema.optional(),
  coverageSummary: z.string().optional(),
  executionExitCode: z.number().nullable().optional(),
  executionStdout: z.string().optional(),
  executionStderr: z.string().optional(),
  executionVerdict: PocExecVerdictSchema.optional(),
  executionDurationMs: z.number().nullable().optional(),
  iterations: z.number(),
  costUsd: z.number().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
  createdAt: z.string().optional(),
  updatedAt: z.string().optional(),
});

export type DynamicAnalysisRunZ = z.infer<typeof DynamicAnalysisRunSchema>;

export const CryptoBehavioralVerdictSchema = z.enum([
  "vulnerable",
  "secure",
  "inconclusive",
  "error",
]);

export const CryptoBehavioralTestTypeSchema = z.enum([
  "timing",
  "ecb-mode",
  "weak-hash",
  "weak-prng",
  "key-length",
  "edge-case",
]);

export const CryptoBehavioralRunSchema = z.object({
  runId: z.string(),
  pipelineRunId: z.string().optional(),
  fingerprint: z.string(),
  repo: z.string(),
  testType: CryptoBehavioralTestTypeSchema,
  verdict: CryptoBehavioralVerdictSchema,
  harnessPath: z.string().nullable().optional(),
  harnessLanguage: z.string().nullable().optional(),
  executionExitCode: z.number().nullable().optional(),
  executionVerdict: PocExecVerdictSchema.optional(),
  executionStdout: z.string().optional(),
  executionStderr: z.string().optional(),
  executionDurationMs: z.number().nullable().optional(),
  tStatistic: z.number().nullable().optional(),
  pValue: z.number().nullable().optional(),
  meanANs: z.number().nullable().optional(),
  meanBNs: z.number().nullable().optional(),
  timingIterations: z.number().nullable().optional(),
  observedBehavior: z.string().optional(),
  expectedBehavior: z.string().optional(),
  algorithmConfirmed: z.string().optional(),
  keyLengthBits: z.number().nullable().optional(),
  costUsd: z.number().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
  createdAt: z.string().optional(),
  updatedAt: z.string().optional(),
});

export type CryptoBehavioralRunZ = z.infer<typeof CryptoBehavioralRunSchema>;

export const PatchResultSchema = z.object({
  patchRunId: z.string(),
  fingerprint: z.string(),
  repo: z.string(),
  diff: z.string().nullable(),
  status: PatchStatusSchema,
  iterations: z.number(),
  buildCommand: z.string().nullable().optional(),
  testCommand: z.string().nullable().optional(),
  worktreePath: z.string().nullable().optional(),
  costUsd: z.number().optional(),
  validatorLog: z.string().optional(),
  history: z.array(
    z.object({
      attempt: z.number(),
      diff: z.string(),
      status: PatchStatusSchema,
      output: z.string(),
    }),
  ),
  createdAt: z.string().optional(),
  updatedAt: z.string().optional(),
});

export type PatchResultZ = z.infer<typeof PatchResultSchema>;

export const FindingMetadataSchema = z.object({
  latestDynamicRunId: z.string().optional(),
  dynamicRunIds: z.array(z.string()).optional(),
  latestPatchRunId: z.string().optional(),
  patchRunIds: z.array(z.string()).optional(),
  latestDynamicStatus: DynamicAnalysisStatusSchema.optional(),
  notes: z.array(z.string()).optional(),
  blame: z
    .object({
      sha: z.string(),
      author: z.string(),
      date: z.string(),
      summary: z.string(),
    })
    .optional(),
  introducedIn: z.string().optional(),
});

export type FindingMetadataZ = z.infer<typeof FindingMetadataSchema>;

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

export const ModelEvidenceAnchorSchema = z.object({
  filePath: z.string(),
  startLine: z.number(),
  description: z.string(),
});

export const ApplicationRouteSchema = z.object({
  id: z.string(),
  method: z.string(),
  path: z.string(),
  filePath: z.string(),
  startLine: z.number(),
  framework: z.string().optional(),
  handlerSymbol: z.string().optional(),
  middleware: z.array(z.string()),
  authMechanisms: z.array(z.string()),
});

export const ApplicationOutboundClientSchema = z.object({
  id: z.string(),
  kind: z.string(),
  filePath: z.string(),
  startLine: z.number(),
  symbol: z.string().optional(),
  targetHint: z.string().optional(),
  protocol: z.string().optional(),
});

export const ApplicationDataStoreSchema = z.object({
  id: z.string(),
  kind: z.string(),
  name: z.string(),
  filePath: z.string(),
  startLine: z.number(),
});

export const ApplicationBackgroundJobSchema = z.object({
  id: z.string(),
  name: z.string(),
  filePath: z.string(),
  startLine: z.number(),
  queue: z.string().optional(),
  handlerSymbol: z.string().optional(),
});

export const ApplicationServiceBoundarySchema = z.object({
  id: z.string(),
  name: z.string(),
  kind: z.enum(["entrypoint", "outbound", "queue", "datastore", "trust-zone"]),
  description: z.string(),
  evidenceAnchors: z.array(ModelEvidenceAnchorSchema),
});

export const ApplicationModelSchema = z.object({
  version: z.string(),
  routes: z.array(ApplicationRouteSchema),
  outboundClients: z.array(ApplicationOutboundClientSchema),
  dataStores: z.array(ApplicationDataStoreSchema),
  backgroundJobs: z.array(ApplicationBackgroundJobSchema),
  serviceBoundaries: z.array(ApplicationServiceBoundarySchema),
  relevantFiles: z.array(z.string()),
  notes: z.array(z.string()),
});

export const ThreatScenarioSchema = z.object({
  id: z.string(),
  detectorId: z.enum([
    "code-config-detect",
    "dangerous-api-detect",
    "auth-access-detect",
    "security-misconfig-detect",
    "ssrf-detect",
    "nosql-injection-detect",
    "prototype-pollution-detect",
    "template-injection-detect",
    "graphql-security-detect",
    "race-condition-detect",
  ]),
  title: z.string(),
  rationale: z.string(),
  attackSurface: z.string(),
  expectedGuard: z.string().optional(),
  relatedFiles: z.array(z.string()),
  relatedSymbols: z.array(z.string()),
  sourceThreatIds: z.array(z.string()),
  cwe: z.array(z.string()),
  entryPoint: z
    .object({
      kind: z.string(),
      filePath: z.string(),
      startLine: z.number(),
      method: z.string().optional(),
      path: z.string().optional(),
      handlerSymbol: z.string().optional(),
    })
    .optional(),
  sink: z
    .object({
      kind: z.string(),
      filePath: z.string(),
      startLine: z.number(),
      symbol: z.string().optional(),
      detail: z.string().optional(),
    })
    .optional(),
  evidenceAnchors: z.array(ModelEvidenceAnchorSchema),
});

export type ApplicationModelZ = z.infer<typeof ApplicationModelSchema>;
export type ThreatScenarioZ = z.infer<typeof ThreatScenarioSchema>;

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
  /**
   * Soft cap on raw scanner findings collected during scan stage.
   * Once exceeded, new findings are dropped and a warning is logged.
   * Distinct from `maxFindings` (triage cap). Field-test issue #34.
   */
  maxRawFindings: z.number().optional(),
  excludePatterns: z.array(z.string()),
  tasks: z.array(z.string()).optional(),
  taskMode: z.enum(["auto", "manual"]).optional(),
  disabledTasks: z.array(z.string()).optional(),
  fresh: z.boolean(),
  diffBase: z.string().optional(),
  agenticReviewContext: z.string().optional(),
});

export type ScanOptsZ = z.infer<typeof ScanOptsSchema>;

// ---------------------------------------------------------------------------
// Agent runtime config
// ---------------------------------------------------------------------------

export const AgentRuntimeCredentialsSchema = z.object({
  apiKey: z.string().optional(),
  baseUrl: z.string().optional(),
});

export const AgentRuntimeConfigSchema = z.object({
  claude: AgentRuntimeCredentialsSchema.optional(),
  piAi: AgentRuntimeCredentialsSchema.optional(),
});

export type AgentRuntimeCredentialsZ = z.infer<typeof AgentRuntimeCredentialsSchema>;
export type AgentRuntimeConfigZ = z.infer<typeof AgentRuntimeConfigSchema>;

export const DiscoveredModuleSchema = z.object({
  name: z.string(),
  path: z.string(),
  includePaths: z.array(z.string()).optional(),
  description: z.string(),
  language: z.string(),
  buildSystem: z.string().optional(),
  moduleKind: z
    .enum([
      "workspace-member",
      "standalone",
      "solution-project",
      "bazel-package",
      "native-root",
      "go-workspace-member",
    ])
    .optional(),
  productPath: z.string().optional(),
  discoveryEvidence: z.array(z.string()).optional(),
});

export const MonorepoConfigSchema = z.object({
  mode: z.enum(["auto", "off"]).optional(),
  modules: z.array(DiscoveredModuleSchema).optional(),
  excludeModules: z.array(z.string()).optional(),
  discoveryModel: z.string().optional(),
  maxModules: z.number().optional(),
});

export type MonorepoConfigZ = z.infer<typeof MonorepoConfigSchema>;

// ---------------------------------------------------------------------------
// KuzushiConfig — the full configuration object
// ---------------------------------------------------------------------------

export const KuzushiConfigSchema = z.object({
  model: z.string(),
  verify: z.boolean().optional(),
  verifyMaxTurns: z.number().optional(),
  verifyConcurrency: z.number().optional(),
  verifyBatchSize: z.number().optional(),
  verifyVerdicts: z.array(VerdictSchema).optional(),
  verifyMinConfidence: z.number().optional(),
  pocHarness: z.boolean().optional(),
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
  scanFindingsBackend: z.enum(["memory", "sqlite"]).optional(),
  triageBatchSize: z.number(),
  triageConcurrency: z.number(),
  scanMode: ScanModeSchema,
  agentRuntimeBackend: AgentRuntimeBackendSchema.optional(),
  agentRuntimeConfig: AgentRuntimeConfigSchema.optional(),
  auth: z.literal("inherited").optional(),
  oauthTokenFile: z.string().optional(),
  tasks: z.array(z.string()),
  severity: z.array(z.string()),
  excludePatterns: z.array(z.string()),
  taskConfig: z.record(z.string(), z.record(z.string(), z.unknown())),
  fpFilterEnabled: z.boolean().optional(),
  fpFilterCustomExclusions: z.array(z.string()).optional(),
  designDecisionClassifier: z.boolean().optional(),
  variantAnalysis: z.boolean().optional(),
  variantAnalysisMaxFindings: z.number().optional(),
  variantRuleSweepEnabled: z.boolean().optional(),
  enableContextEnrichment: z.boolean().optional(),
  ensembleModels: z.array(z.string()).optional(),
  diffBase: z.string().optional(),
  taintDiffBase: z.string().optional(),
  taintDiffMode: z.enum(["delta", "baseline"]).optional(),
  taintGroundingEnabled: z.boolean().optional(),
  astIndexEnabled: z.boolean().optional(),
  callGraphAssistEnabled: z.boolean().optional(),
  dynamicAnalysisEnabled: z.boolean().optional(),
  cryptoBehavioralTestEnabled: z.boolean().optional(),
  cryptoBehavioralTimeoutMs: z.number().optional(),
  cryptoBehavioralMaxFindings: z.number().optional(),
  cryptoBehavioralPerFindingBudgetUsd: z.number().optional(),
  coverageGuidedEnabled: z.boolean().optional(),
  dynamicMaxIterations: z.number().optional(),
  dynamicMaxCandidates: z.number().optional(),
  dynamicMinScore: z.number().optional(),
  dynamicPerFindingBudgetUsd: z.number().optional(),
  patchingEnabled: z.boolean().optional(),
  patchMaxIterations: z.number().optional(),
  patchBuildCommand: z.string().optional(),
  patchTestCommand: z.string().optional(),
  autoPatchEnabled: z.boolean().optional(),
  autoPatchAfter: z.enum(["verify", "poc", "triage"]).optional(),
  patchVerifyDepth: z.enum(["task", "triage", "full"]).optional(),
  patchConcurrency: z.number().int().positive().optional(),
  llmRescoreEnabled: z.boolean().optional(),
  llmRescoreThreshold: z.number().optional(),
  chainAnalysis: z.boolean().optional(),
  precedentsPath: z.string().optional(),
  securityProfilesPath: z.string().optional(),
  prioritizeFindings: z.boolean().optional(),
  costBudgetUsd: z.number().optional(),
  triageMaxFindings: z.number().int().positive().optional(),
  triageMinScore: z.number().min(0).max(100).optional(),
  enableDynamicTaskSelection: z.boolean().optional(),
  pocExecute: z.boolean().optional(),
  pocSandbox: PocSandboxSchema.optional(),
  pocExecTimeoutMs: z.number().optional(),
  pocRefinementMaxIterations: z.number().optional(),
  pocReflectionInterval: z.number().optional(),
  verifyRefinementMaxIterations: z.number().optional(),
  verifyReflectionInterval: z.number().optional(),
  confidenceCalibration: z.boolean().optional(),
  confidenceSignalWeights: z
    .object({
      taskId: z.number().optional(),
      triage: z.number().optional(),
      verification: z.number().optional(),
      history: z.number().optional(),
      context: z.number().optional(),
    })
    .optional(),
  trajectoryMemory: z.boolean().optional(),
  trajectoryMaxExemplars: z.number().optional(),
  triageStrategy: TriageStrategySchema.optional(),
  triageSpecialistMaxTurns: z.number().nullable().optional(),
  triageAssertions: z
    .object({
      enabled: z.boolean().optional(),
      weights: z
        .object({
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
        })
        .optional(),
    })
    .optional(),
  qualityGates: z
    .object({
      failOnHighSeverityTP: z.boolean().optional(),
      maxOpenFindings: z.number().optional(),
      minTriageConfidence: z.number().optional(),
      failOnExploitable: z.boolean().optional(),
    })
    .optional(),
  jsonOutput: z.string().optional(),
  csvOutput: z.string().optional(),
  jsonlOutput: z.string().optional(),
  hooks: z
    .object({
      files: z.array(z.string()).optional(),
    })
    .optional(),
  enableExternalHooks: z.boolean().optional(),
  triagePromptFile: z.string().optional(),
  verifyPromptFile: z.string().optional(),
  bootstrapFiles: z
    .object({
      files: z.array(z.string()).optional(),
      maxCharsPerFile: z.number().optional(),
      totalMaxChars: z.number().optional(),
    })
    .optional(),
  toolPolicies: z
    .record(
      z.string(),
      z.object({
        allow: z.array(z.string()).optional(),
        deny: z.array(z.string()).optional(),
      }),
    )
    .optional(),
  modelFallbacks: z.record(z.string(), z.array(z.string())).optional(),
  modelFallbackCooldownMs: z.number().optional(),
  streamingEnabled: z.boolean().optional(),
  streamingPort: z.number().int().nonnegative().optional(),
  incrementalCache: z.boolean().optional(),
  incrementalDepTracking: z.boolean().optional(),
  incrementalCacheTtlDays: z.number().int().positive().optional(),
  skipTriageForHighConfidenceAgentic: z.boolean().optional(),
  monorepo: MonorepoConfigSchema.optional(),
});

export type KuzushiConfigZ = z.infer<typeof KuzushiConfigSchema>;

// ---------------------------------------------------------------------------
// FindingRow (SQLite persistence)
// ---------------------------------------------------------------------------

export const FindingRowSchema = z.object({
  taskId: z.string(),
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
  pocRunExitCode: z.number().nullable().optional(),
  pocRunStdout: z.string().nullable().optional(),
  pocRunStderr: z.string().nullable().optional(),
  pocRunVerdict: PocExecVerdictSchema.nullable().optional(),
  pocRunDurationMs: z.number().nullable().optional(),
  compositeConfidence: z.number().nullable().optional(),
  confidenceSignalsJson: z.string().nullable().optional(),
  taintPathJson: z.string().nullable().optional(),
  proofState: ProofStateSchema.nullable().optional(),
  engineProvenanceJson: z.string().nullable().optional(),
  findingMetadataJson: z.string().nullable().optional(),
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
  title: z.string().optional(),
  attack_narrative: z.string().nullable().optional(),
  display_severity: DisplaySeveritySchema.optional(),
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
  evidence_trail: z.array(z.object({ level: z.string(), evidence: z.string() })).optional(),
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
  code_citations: z
    .array(
      z.object({
        file_path: z.string(),
        start_line: z.number(),
        end_line: z.number(),
        snippet: z.string(),
        description: z.string(),
      }),
    )
    .optional(),
  attack_path: z
    .object({
      chain: z.array(z.string()),
      narrative: z.string(),
      likelihood_reasoning: z.string(),
      impact_reasoning: z.string(),
    })
    .optional(),
  assumptions: z.array(z.string()).optional(),
  controls: z
    .array(
      z.object({
        name: z.string(),
        description: z.string(),
        file_path: z.string().optional(),
      }),
    )
    .optional(),
  blindspots: z.array(z.string()).optional(),
  source_threat_ids: z.array(z.string()).optional(),
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
  code_citations: z
    .array(
      z.object({
        file_path: z.string(),
        start_line: z.number(),
        end_line: z.number(),
        snippet: z.string(),
        description: z.string(),
      }),
    )
    .optional(),
  attack_path: z
    .object({
      chain: z.array(z.string()),
      narrative: z.string(),
      likelihood_reasoning: z.string(),
      impact_reasoning: z.string(),
    })
    .optional(),
  assumptions: z.array(z.string()).optional(),
  controls: z
    .array(
      z.object({
        name: z.string(),
        description: z.string(),
        file_path: z.string().optional(),
      }),
    )
    .optional(),
  blindspots: z.array(z.string()).optional(),
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
export function formatValidationErrorMessage(label: string, errors: ValidationError[]): string {
  const details = errors.map((e) => `  - ${e.path}: ${e.message}`).join("\n");
  return `${label} validation failed:\n${details}`;
}

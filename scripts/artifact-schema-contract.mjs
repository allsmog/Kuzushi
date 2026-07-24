import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { Validator } from "@cfworker/json-schema";
import { checkFieldShapeSpecs } from "./artifact-schema-shapes.mjs";
import {
  optionalRunArtifactSpecs,
  requiredRunArtifactSpecs,
  toolInputArtifactSpecs,
  toolResultArtifactSpecs,
} from "./canonical-run-artifacts.mjs";
import { canonicalRunSchemaFiles } from "./canonical-run-schema-files.mjs";

export { canonicalRunSchemaFiles };

const FIXTURE_MODEL_FIELD = "model";

const artifactFieldGroups = [
  { path: ["definitions", "artifact"], kind: "required", fields: ["label", "path", "kind"] },
];
const reservedArtifactMetadataSpecs = [
  ...requiredRunArtifactSpecs,
  ...optionalRunArtifactSpecs,
  ...toolInputArtifactSpecs,
  ...toolResultArtifactSpecs,
];
const retiredArtifactMetadataSpecsBySchema = {
  "schemas/run.artifacts.schema.json": [{ path: "trace.jsonl", label: "runtime trace" }],
};

const producerFixturesBySchema = {
  "schemas/run.events.schema.json": [
    {
      name: "sast scan completion",
      value: {
        n: 2,
        kind: "scan",
        status: "completed",
        message: "sast:scan completed: 2 finding(s)",
        atUnix: 1,
        tool: "sast:scan",
      },
    },
    {
      name: "stale-run recovery",
      value: {
        n: 3,
        kind: "run",
        status: "interrupted",
        message: "run process is no longer running",
        atUnix: 2,
      },
    },
  ],
  "schemas/run.items.schema.json": runItemProducerFixtures(),
  "schemas/run.summary.schema.json": [
    {
      name: "agent llm audit summary",
      value: {
        runId: "shell-agent",
        kind: "shell",
        status: "completed",
        target: "/tmp/repo",
        startedAtUnix: 1,
        completedAtUnix: 2,
        llmCalls: [
          {
            n: 2,
            kind: "llm",
            [FIXTURE_MODEL_FIELD]: "openai:gpt-test",
            provider: "openai",
            promptHash: "fnv1a64:test",
            latencyMs: 120,
          },
        ],
      },
    },
  ],
};

function runItemProducerFixtures() {
  const context = runItemFixtureContext();
  const items = [
    ...planAndTaskFixtures(context),
    ...requestedAndRejectedToolFixtures(context),
    ...runningToolFixtures(context),
    ...finishedToolFixtures(context),
    ...modelCallFixtures(context),
    ...evidenceItemFixtures(context),
    ...operatorItemFixtures(context),
    ...terminalOutcomeFixtures(context),
    ...phaseReceiptFixtures(context),
  ];
  return items.map(({ name, item, envelope }) => ({
    name,
    value: runItemEnvelope(item, envelope),
  }));
}

function runItemFixtureContext() {
  const cost = { observedUsd: 0, completeness: "exact" };
  const fingerprint = `blake3:${"a".repeat(64)}`;
  const itemId = "00000000-0000-4000-8000-000000000002";
  const taskId = "00000000-0000-4000-8000-000000000003";
  const callId = "00000000-0000-4000-8000-000000000004";
  const questionId = "00000000-0000-4000-8000-000000000005";
  const artifact = {
    path: "result.json",
    kind: "json",
    label: "tool result",
    digest: "sha256:result",
    byteCount: 42,
    lineCount: 1,
    producingItemId: itemId,
  };
  const findingDelta = {
    added: 1,
    updated: 0,
    removed: 0,
    storeWatermark: "ledger:1",
    findingIdSamples: ["finding-1"],
  };
  const noFurtherAction = { kind: "no_further_action", reason: "run terminal" };
  return {
    cost,
    fingerprint,
    itemId,
    taskId,
    callId,
    questionId,
    artifact,
    findingDelta,
    noFurtherAction,
  };
}

function planAndTaskFixtures({ taskId }) {
  return [
    {
      name: "plan updated",
      item: {
        type: "plan_updated",
        revision: 1,
        title: "Scan plan",
        status: "running",
        task_ids: [taskId],
      },
    },
    {
      name: "task updated",
      envelope: { taskId },
      item: {
        type: "task_updated",
        title: "Scan target",
        status: "running",
        detail: "Scanning",
      },
    },
  ];
}

function requestedAndRejectedToolFixtures({ callId, fingerprint }) {
  return [
    {
      name: "tool call requested",
      envelope: { callId },
      item: {
        type: "tool_call_requested",
        tool_name: "sast:scan",
        operation_fingerprint: fingerprint,
        safe_option_names: ["target"],
      },
    },
    {
      name: "tool call rejected",
      envelope: { callId },
      item: {
        type: "tool_call_rejected",
        reason_class: "autonomy_policy",
        detail: "Operator posture blocks this tool",
      },
    },
  ];
}

function runningToolFixtures({ callId }) {
  return [
    {
      name: "tool call started",
      envelope: { callId },
      item: {
        type: "tool_call_started",
        tool_name: "sast:scan",
        runtime: "codex",
        model: "test:model",
      },
    },
    {
      name: "tool call progress",
      envelope: { callId },
      item: {
        type: "tool_call_progress",
        message: "Scanning files",
        completed: 12,
        total: 40,
      },
    },
  ];
}

function finishedToolFixtures({ callId, cost, artifact }) {
  return [
    {
      name: "tool call finished",
      envelope: { callId },
      item: {
        type: "tool_call_finished",
        status: "completed",
        cost,
        result_artifact: artifact,
        preview: ["Scan completed"],
        warning_count: 0,
        error_count: 0,
      },
    },
  ];
}

function modelCallFixtures({ callId, cost, fingerprint }) {
  return [
    {
      name: "model call started",
      envelope: { callId },
      item: {
        type: "model_call_started",
        provider: "openai",
        model: "test:model",
        operation_fingerprint: fingerprint,
      },
    },
    {
      name: "model call finished",
      envelope: { callId },
      item: {
        type: "model_call_finished",
        provider: "openai",
        model: "test:model",
        status: "completed",
        latency_ms: 120,
        usage: { inputTokens: 10, outputTokens: 4 },
        cost,
      },
    },
  ];
}

function evidenceItemFixtures({ artifact, findingDelta, itemId }) {
  return [
    {
      name: "safe reasoning summary",
      item: {
        type: "safe_reasoning_summary",
        text: "Inspected the reachable call path",
        redaction_policy_version: 1,
      },
    },
    {
      name: "artifact produced",
      item: { type: "artifact_produced", artifact },
    },
    {
      name: "finding delta",
      item: { type: "finding_delta", delta: findingDelta },
    },
    {
      name: "diagnostic notice",
      item: {
        type: "diagnostic_notice",
        level: "warning",
        message: "One optional engine was unavailable",
      },
    },
    {
      name: "progress truncated",
      item: {
        type: "progress_truncated",
        progress_item_id: itemId,
        omitted_count: 3,
      },
    },
  ];
}

function operatorItemFixtures({ questionId }) {
  return [
    {
      name: "operator question",
      item: {
        type: "operator_question",
        question_id: questionId,
        prompt: "Continue?",
        choices: [{ id: "continue", label: "Continue" }],
        authorization_scope: "sast:scan",
      },
    },
    {
      name: "operator decision",
      item: {
        type: "operator_decision",
        question_id: questionId,
        decision: { kind: "selected", choice_id: "continue" },
        authorization_scope: "sast:scan",
      },
    },
  ];
}

function terminalOutcomeFixtures({ noFurtherAction }) {
  return [
    {
      name: "terminal outcome",
      item: {
        type: "terminal_outcome",
        status: "blocked",
        summary: "Run blocked by policy",
        cost: { observedUsd: 0, completeness: "incomplete_observed" },
        continuation: noFurtherAction,
      },
    },
  ];
}

function phaseReceiptFixtures({ cost, findingDelta, itemId, questionId, noFurtherAction }) {
  return [
    {
      name: "phase receipt",
      item: {
        type: "phase_receipt",
        run_ids: ["run-previous"],
        status: "partial",
        cost,
        finding_delta: findingDelta,
        artifact_ids: [itemId],
        interaction_count: 1,
        offered_actions: [
          { kind: "open_phase", phase: "review" },
          { kind: "open_report", reason: "Review complete" },
          { kind: "inspect_run", run_id: "run-previous", reason: "Inspect evidence" },
          { kind: "retry", reason: "Retry failed work" },
          { kind: "await_decision", question_id: questionId },
          noFurtherAction,
        ],
        continuation: { kind: "retry", reason: "Retry failed work" },
      },
    },
  ];
}

function runItemEnvelope(item, overrides = {}) {
  return {
    schemaVersion: 1,
    seq: 1,
    eventId: "00000000-0000-4000-8000-000000000001",
    itemId: "00000000-0000-4000-8000-000000000002",
    runId: "run-1",
    source: "workflow",
    occurredAtMs: 120,
    prevEventHash: `sha256:${"c".repeat(64)}`,
    eventHash: `sha256:${"b".repeat(64)}`,
    item,
    ...overrides,
  };
}

function runItemRejectedFixtures() {
  return [
    ...missingRunItemFieldFixtures(),
    ...terminalContractRejections(),
    ...interactionContractRejections(),
    ...envelopeIdentityRejections(),
    ...artifactAndQuestionIdentityRejections(),
    ...progressAndReceiptIdentityRejections(),
    ...unknownFieldRejections(),
  ];
}

function missingRunItemFieldFixtures() {
  return runItemProducerFixtures().flatMap(({ name, value }) =>
    (requiredRunItemFields[value.item.type] ?? []).map((field) => {
      const item = { ...value.item };
      delete item[field];
      return {
        name: `${name} missing ${field}`,
        value: { ...value, item },
      };
    }),
  );
}

function terminalContractRejections() {
  return [
    {
      name: "terminal outcome missing its payload",
      value: runItemEnvelope({ type: "terminal_outcome" }),
    },
    {
      name: "terminal outcome with a nonterminal status",
      value: runItemEnvelope({
        type: "terminal_outcome",
        status: "running",
        summary: "Still running",
        cost: { observedUsd: 0, completeness: "exact" },
        continuation: { kind: "no_further_action", reason: "not terminal" },
      }),
    },
    {
      name: "unavailable cost with an observed amount",
      value: runItemEnvelope({
        type: "terminal_outcome",
        status: "failed",
        summary: "Run failed",
        cost: { observedUsd: 1, completeness: "unavailable" },
        continuation: { kind: "retry", reason: "Retry" },
      }),
    },
  ];
}

function interactionContractRejections() {
  return [
    {
      name: "tool progress with only one counter",
      value: runItemEnvelope({
        type: "tool_call_progress",
        message: "Scanning",
        completed: 1,
      }),
    },
    {
      name: "selected operator decision without a choice",
      value: runItemEnvelope({
        type: "operator_decision",
        question_id: "00000000-0000-4000-8000-000000000005",
        decision: { kind: "selected" },
        authorization_scope: "sast:scan",
      }),
    },
  ];
}

function envelopeIdentityRejections() {
  const notice = {
    type: "diagnostic_notice",
    level: "info",
    message: "Invalid envelope identity",
  };
  return [
    {
      name: "non-UUID typed item identity",
      value: { ...runItemEnvelope(notice), itemId: "item-1" },
    },
    {
      name: "unsafe run identity",
      value: { ...runItemEnvelope(notice), runId: "../outside" },
    },
    {
      name: "short event hash",
      value: { ...runItemEnvelope(notice), eventHash: "sha256:short" },
    },
  ];
}

function artifactAndQuestionIdentityRejections() {
  return [
    {
      name: "artifact with a non-UUID producing item",
      value: runItemEnvelope({
        type: "artifact_produced",
        artifact: {
          path: "result.json",
          kind: "json",
          label: "tool result",
          digest: "sha256:result",
          byteCount: 42,
          producingItemId: "item-1",
        },
      }),
    },
    {
      name: "operator question with a non-UUID question identity",
      value: runItemEnvelope({
        type: "operator_question",
        question_id: "question-1",
        prompt: "Continue?",
        authorization_scope: "sast:scan",
      }),
    },
  ];
}

function progressAndReceiptIdentityRejections() {
  return [
    {
      name: "progress truncation with a non-UUID item identity",
      value: runItemEnvelope({
        type: "progress_truncated",
        progress_item_id: "progress-1",
        omitted_count: 1,
      }),
    },
    {
      name: "phase receipt with an unsafe run identity",
      value: runItemEnvelope({
        type: "phase_receipt",
        run_ids: ["../outside"],
        status: "partial",
        cost: { observedUsd: 0, completeness: "exact" },
        finding_delta: {
          added: 0,
          updated: 0,
          removed: 0,
          storeWatermark: "ledger:1",
        },
        artifact_ids: [],
        interaction_count: 0,
        offered_actions: [],
        continuation: { kind: "retry", reason: "Retry" },
      }),
    },
  ];
}

function unknownFieldRejections() {
  return [
    {
      name: "run item with an unknown field",
      value: runItemEnvelope({
        type: "diagnostic_notice",
        level: "info",
        message: "Unexpected field",
        unexpected: true,
      }),
    },
    {
      name: "continuation with an unknown field",
      value: runItemEnvelope({
        type: "terminal_outcome",
        status: "failed",
        summary: "Run failed",
        cost: { observedUsd: 0, completeness: "unavailable" },
        continuation: { kind: "retry", reason: "Retry", unexpected: true },
      }),
    },
    {
      name: "operator decision with an unknown field",
      value: runItemEnvelope({
        type: "operator_decision",
        question_id: "00000000-0000-4000-8000-000000000005",
        decision: { kind: "approved", unexpected: true },
        authorization_scope: "sast:scan",
      }),
    },
  ];
}

function runItemStructuralOnlyFixtures() {
  return [
    {
      name: "progress completed exceeds total",
      value: runItemEnvelope({
        type: "tool_call_progress",
        message: "Scanning",
        completed: 2,
        total: 1,
      }),
    },
    {
      name: "unredacted SafeText secret",
      value: runItemEnvelope({
        type: "diagnostic_notice",
        level: "warning",
        message: "Authorization: Bearer raw-secret",
      }),
    },
    {
      name: "SafeText control character",
      value: runItemEnvelope({
        type: "diagnostic_notice",
        level: "warning",
        message: "unsafe\u0007control",
      }),
    },
  ];
}

const requiredRunItemFields = {
  plan_updated: ["type", "revision", "title", "status", "task_ids"],
  task_updated: ["type", "title", "status"],
  tool_call_requested: ["type", "tool_name", "operation_fingerprint"],
  tool_call_rejected: ["type", "reason_class", "detail"],
  tool_call_started: ["type", "tool_name"],
  tool_call_progress: ["type", "message"],
  tool_call_finished: ["type", "status", "cost", "warning_count", "error_count"],
  model_call_started: ["type", "provider", "model", "operation_fingerprint"],
  model_call_finished: ["type", "provider", "model", "status", "latency_ms", "usage", "cost"],
  safe_reasoning_summary: ["type", "text", "redaction_policy_version"],
  artifact_produced: ["type", "artifact"],
  finding_delta: ["type", "delta"],
  diagnostic_notice: ["type", "level", "message"],
  operator_question: ["type", "question_id", "prompt", "authorization_scope"],
  operator_decision: ["type", "question_id", "decision", "authorization_scope"],
  terminal_outcome: ["type", "status", "summary", "cost", "continuation"],
  phase_receipt: [
    "type",
    "run_ids",
    "status",
    "cost",
    "finding_delta",
    "artifact_ids",
    "interaction_count",
    "offered_actions",
    "continuation",
  ],
  progress_truncated: ["type", "progress_item_id", "omitted_count"],
};

const rejectedFixturesBySchema = {
  "schemas/run.items.schema.json": runItemRejectedFixtures(),
};

const structuralOnlyFixturesBySchema = {
  "schemas/run.items.schema.json": runItemStructuralOnlyFixtures(),
};

const requiredAliasGroupsBySchema = {
  "schemas/run.artifacts.schema.json": [
    { path: [], kind: "required", fields: ["runId", "artifacts"] },
    ...artifactFieldGroups,
  ],
  "schemas/run.events.schema.json": [
    { path: [], kind: "required", fields: ["atUnix"] },
    ...artifactFieldGroups,
  ],
  "schemas/run.failures.schema.json": [
    { path: [], kind: "required", fields: ["runId"] },
    {
      path: ["definitions", "failure"],
      kind: "required",
      fields: ["agentThreadContext"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["failedStage"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["whatFailed"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["artifactsAvailable"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["missingArtifacts"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["allowedProofLevel"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["nextFilesOrArtifactsToInspect"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["recoveryOptions"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["fallbackPrompt"],
    },
    {
      path: ["definitions", "failureContext"],
      kind: "required",
      fields: ["claimsForbidden"],
    },
    ...artifactFieldGroups,
  ],
  "schemas/run.summary.schema.json": [
    { path: [], kind: "required", fields: ["runId", "startedAtUnix"] },
    { path: [], kind: "declared", fields: ["lifecycleMalformedItems"] },
    { path: ["definitions", "llmCall"], kind: "required", fields: ["promptHash"] },
    {
      path: ["definitions", "llmCall"],
      kind: "declared",
      fields: ["latencyMs", "costUsd"],
    },
    ...artifactFieldGroups,
  ],
  "schemas/run.items.schema.json": [
    {
      path: [],
      kind: "required",
      fields: [
        "schemaVersion",
        "seq",
        "eventId",
        "itemId",
        "runId",
        "source",
        "occurredAtMs",
        "eventHash",
        "item",
      ],
    },
    { path: ["definitions", "runItem"], kind: "required", fields: ["type"] },
  ],
};

const snapshotEnvelopeFieldsBySchema = {};

const routePatternBySchema = {};

const proofStateEnumBySchema = {};

const proofStateRefBySchema = {};

const expectedProofStates = [
  "signal_only",
  "code_cited",
  "source_sink_linked",
  "sanitizer_checked",
  "statically_confirmed",
  "statically_rejected",
  "needs_runtime_evidence",
  "execution_confirmed",
  "runtime_confirmed",
  "dynamic_confirmed",
  "exploit_confirmed",
  "poc_confirmed",
  "runtime_reviewed",
  "execution_attempted",
  "execution_rejected",
];

const artifactKindSpec = (refs) => ({
  name: "artifactKind",
  path: ["definitions", "artifactKind"],
  values: ["json", "jsonl", "markdown", "sarif", "directory", "artifact"],
  refs,
});
const runStatusSpec = (refs) => ({
  name: "runStatus",
  path: ["definitions", "runStatus"],
  values: ["running", "completed", "failed", "interrupted", "partial", "skipped", "paused"],
  refs,
});
const runSummaryStatusSpec = {
  name: "runSummaryStatus",
  path: ["properties", "status"],
  values: ["running", "completed", "failed", "interrupted", "partial", "skipped", "paused"],
  refs: [],
};
const llmCallKindValues = [
  "tool",
  "reasoning",
  "tool-progress",
  "done",
  "refused",
  "plan",
  "llm",
  "critic",
];

const schemaEnumSpecs = {
  "schemas/run.artifacts.schema.json": [
    artifactKindSpec([["definitions", "artifact", "properties", "kind"]]),
  ],
  "schemas/run.failures.schema.json": [
    artifactKindSpec([["definitions", "artifact", "properties", "kind"]]),
    runStatusSpec([
      ["properties", "status"],
      ["definitions", "failure", "properties", "status"],
    ]),
  ],
  "schemas/run.events.schema.json": [
    {
      name: "eventKind",
      path: ["definitions", "eventKind"],
      values: ["tool", "scan", "run", "shell"],
      refs: [["properties", "kind"]],
    },
    {
      name: "eventStatus",
      path: ["definitions", "eventStatus"],
      values: ["started", "running", "completed", "failed", "partial", "skipped", "paused"],
      refs: [["properties", "status"]],
    },
    artifactKindSpec([["definitions", "artifact", "properties", "kind"]]),
  ],
  "schemas/run.items.schema.json": [
    {
      name: "runItemType",
      path: ["definitions", "runItemType"],
      values: [
        "plan_updated",
        "task_updated",
        "tool_call_requested",
        "tool_call_rejected",
        "tool_call_started",
        "tool_call_progress",
        "tool_call_finished",
        "model_call_started",
        "model_call_finished",
        "safe_reasoning_summary",
        "artifact_produced",
        "finding_delta",
        "diagnostic_notice",
        "operator_question",
        "operator_decision",
        "terminal_outcome",
        "phase_receipt",
        "progress_truncated",
      ],
      refs: [["definitions", "runItem", "properties", "type"]],
    },
    {
      name: "runItemSource",
      path: ["definitions", "runItemSource"],
      values: ["dispatch", "runtime", "workflow", "operator", "persistence"],
      refs: [["properties", "source"]],
    },
    {
      name: "runItemStatus",
      path: ["definitions", "runItemStatus"],
      values: [
        "pending",
        "running",
        "completed",
        "partial",
        "skipped",
        "blocked",
        "failed",
        "canceled",
        "interrupted",
      ],
      refs: [
        ["definitions", "planUpdatedItem", "properties", "status"],
        ["definitions", "taskUpdatedItem", "properties", "status"],
      ],
    },
    {
      name: "terminalRunItemStatus",
      path: ["definitions", "terminalRunItemStatus"],
      values: ["completed", "partial", "skipped", "blocked", "failed", "canceled", "interrupted"],
      refs: [
        ["definitions", "toolCallFinishedItem", "properties", "status"],
        ["definitions", "modelCallFinishedItem", "properties", "status"],
        ["definitions", "terminalOutcomeItem", "properties", "status"],
        ["definitions", "phaseReceiptItem", "properties", "status"],
      ],
    },
    {
      name: "workflowPhase",
      path: ["definitions", "workflowPhase"],
      values: ["map", "scan", "review", "prove", "fix"],
      refs: [
        ["properties", "phase"],
        ["definitions", "openPhaseContinuation", "properties", "phase"],
      ],
    },
    {
      name: "workflowContinuationKind",
      path: ["definitions", "workflowContinuationKind"],
      values: [
        "open_phase",
        "open_report",
        "inspect_run",
        "retry",
        "await_decision",
        "no_further_action",
      ],
      refs: [["definitions", "workflowContinuation", "properties", "kind"]],
    },
    {
      name: "operatorDecisionKind",
      path: ["definitions", "operatorDecisionKind"],
      values: ["selected", "provided_freeform", "approved", "denied", "deferred"],
      refs: [["definitions", "operatorDecision", "properties", "kind"]],
    },
    {
      name: "diagnosticLevel",
      path: ["definitions", "diagnosticLevel"],
      values: ["info", "warning", "error"],
      refs: [["definitions", "diagnosticNoticeItem", "properties", "level"]],
    },
    {
      name: "runtimeCostCompleteness",
      path: ["definitions", "runtimeCostCompleteness"],
      values: ["exact", "incomplete_observed", "unavailable"],
      refs: [["definitions", "runtimeCost", "properties", "completeness"]],
    },
  ],
  "schemas/run.summary.schema.json": [
    runSummaryStatusSpec,
    {
      name: "runKind",
      path: ["definitions", "runKind"],
      values: ["run", "tool", "scan", "shell"],
      refs: [["properties", "kind"]],
    },
    {
      name: "llmCallKind",
      path: ["definitions", "llmCallKind"],
      values: llmCallKindValues,
      refs: [["definitions", "llmCall", "properties", "kind"]],
    },
    artifactKindSpec([["definitions", "artifact", "properties", "kind"]]),
  ],
};

for (const [file, fields] of Object.entries(snapshotEnvelopeFieldsBySchema)) {
  requiredAliasGroupsBySchema[file].push({ path: [], kind: "declared", fields });
}

export function checkCanonicalRunSchemas(root) {
  return [
    ...checkSchemaInventory(root, canonicalRunSchemaFiles),
    ...canonicalRunSchemaFiles.flatMap((file) => checkSchemaFile(root, file)),
  ];
}

function checkSchemaInventory(root, expectedFiles) {
  const actualFiles = readdirSync(path.join(root, "schemas"))
    .filter((file) => /^run\..*\.schema\.json$/.test(file))
    .map((file) => `schemas/${file}`)
    .sort();
  return [
    ...missingEntries(expectedFiles, actualFiles, "missing canonical schema"),
    ...missingEntries(actualFiles, expectedFiles, "unlisted canonical schema"),
  ];
}

function missingEntries(source, allowed, label) {
  return source.filter((entry) => !allowed.includes(entry)).map((entry) => `${label}: ${entry}`);
}

function checkSchemaFile(root, relativeFile) {
  const absoluteFile = path.join(root, relativeFile);
  if (!existsSync(absoluteFile)) return [`schema contract: missing ${relativeFile}`];
  const schema = readSchema(absoluteFile);
  if (schema === null) return [`schema contract: ${relativeFile} is not parseable JSON`];
  return checkSchemaDocument(relativeFile, schema);
}

function readSchema(absoluteFile) {
  try {
    return JSON.parse(readFileSync(absoluteFile, "utf8"));
  } catch {
    return null;
  }
}

function checkSchemaDocument(relativeFile, schema) {
  const schemaName = path.basename(relativeFile);
  const expectedId = `https://kuzushi.dev/schemas/${schemaName}`;
  return [
    schema["$schema"] === "http://json-schema.org/draft-07/schema#"
      ? null
      : `${relativeFile}: missing draft-07 $schema`,
    schema["$id"] === expectedId ? null : `${relativeFile}: expected $id ${expectedId}`,
    typeof schema.title === "string" && schema.title.includes("Kuzushi")
      ? null
      : `${relativeFile}: title must identify Kuzushi`,
    schemaAcceptsObject(schema) ? null : `${relativeFile}: root type must accept object payloads`,
    isPlainObject(schema.properties) ? null : `${relativeFile}: missing root properties object`,
    ...checkRequiredAliasGroups(relativeFile, schema),
    ...checkRoutePatterns(relativeFile, schema),
    ...checkProofStateEnums(relativeFile, schema),
    ...checkProofStateRefs(relativeFile, schema),
    ...checkProofLevelNumericBranch(relativeFile, schema),
    ...checkFieldShapeSpecs(relativeFile, schema, schemaNode),
    ...checkRunArtifactManifestReservedMetadata(relativeFile, schema),
    ...checkRetiredArtifactMetadata(relativeFile, schema),
    ...checkNamedEnums(relativeFile, schema),
    ...checkRunItemVariantUnion(relativeFile, schema),
    ...checkRunItemStructuralContract(relativeFile, schema),
    ...checkProducerFixtures(relativeFile, schema),
    ...checkRejectedFixtures(relativeFile, schema),
    ...checkStructuralOnlyFixtures(relativeFile, schema),
  ].filter(Boolean);
}

function checkProducerFixtures(relativeFile, schema) {
  const fixtures = producerFixturesBySchema[relativeFile] ?? [];
  if (fixtures.length === 0) return [];
  const validator = new Validator(schema, "7", false);
  return fixtures.flatMap(({ name, value }) => {
    const result = validator.validate(value);
    return result.valid
      ? []
      : [`${relativeFile}: producer fixture ${name} is invalid: ${JSON.stringify(result.errors)}`];
  });
}

function checkRejectedFixtures(relativeFile, schema) {
  const fixtures = rejectedFixturesBySchema[relativeFile] ?? [];
  if (fixtures.length === 0) return [];
  const validator = new Validator(schema, "7", false);
  return fixtures.flatMap(({ name, value }) => {
    const result = validator.validate(value);
    return result.valid ? [`${relativeFile}: malformed fixture ${name} was accepted`] : [];
  });
}

function checkStructuralOnlyFixtures(relativeFile, schema) {
  const fixtures = structuralOnlyFixturesBySchema[relativeFile] ?? [];
  if (fixtures.length === 0) return [];
  const validator = new Validator(schema, "7", false);
  return fixtures.flatMap(({ name, value }) => {
    const result = validator.validate(value);
    return result.valid
      ? []
      : [
          `${relativeFile}: structural-only fixture ${name} was rejected: ${JSON.stringify(result.errors)}`,
        ];
  });
}

function checkRunItemVariantUnion(relativeFile, schema) {
  if (relativeFile !== "schemas/run.items.schema.json") return [];
  return [
    ...checkRunItemSchemaUnion(relativeFile, schema),
    ...checkClosedTaggedUnionBranches(relativeFile, schema),
  ];
}

function checkRunItemSchemaUnion(relativeFile, schema) {
  const itemTypes = schemaNode(schema, ["definitions", "runItemType", "enum"]);
  if (!Array.isArray(itemTypes)) {
    return [`${relativeFile}: missing discriminated run-item variant union`];
  }
  return checkRunItemSchemaVariants(relativeFile, schema, itemTypes);
}

function checkRunItemSchemaVariants(relativeFile, schema, itemTypes) {
  const variants = schemaNode(schema, ["definitions", "runItem", "oneOf"]);
  if (!Array.isArray(variants)) {
    return [`${relativeFile}: missing discriminated run-item variant union`];
  }
  const branches = variants.map((variant) => runItemBranch(schema, variant));
  return runItemSchemaVariantErrors(relativeFile, itemTypes, branches);
}

function runItemBranch(schema, variant) {
  const definitionName = variant?.$ref?.replace("#/definitions/", "");
  const definition = definitionName && schemaNode(schema, ["definitions", definitionName]);
  return { definition, itemType: definition?.properties?.type?.const };
}

function runItemSchemaVariantErrors(relativeFile, itemTypes, branches) {
  const branchTypes = branches.map(({ itemType }) => itemType).filter(Boolean);
  const duplicates = branchTypes.filter(
    (itemType, index) => branchTypes.indexOf(itemType) !== index,
  );
  const producerTypes = runItemProducerFixtures().map(({ value }) => value.item.type);
  const requiredFieldTypes = Object.keys(requiredRunItemFields);
  return [
    ...branches.flatMap((branch) => runItemBranchErrors(relativeFile, branch)),
    ...missingEntries(itemTypes, branchTypes, `${relativeFile}: missing run-item branch`),
    ...missingEntries(branchTypes, itemTypes, `${relativeFile}: unknown run-item branch`),
    ...missingEntries(itemTypes, producerTypes, `${relativeFile}: missing producer fixture`),
    ...missingEntries(itemTypes, requiredFieldTypes, `${relativeFile}: missing required-field map`),
    ...[...new Set(duplicates)].map(
      (itemType) => `${relativeFile}: duplicate run-item branch ${itemType}`,
    ),
  ];
}

function runItemBranchErrors(relativeFile, { definition, itemType }) {
  if (typeof itemType !== "string") {
    return [`${relativeFile}: run-item branch lacks a type const`];
  }
  const required = requiredFields(definition);
  return (requiredRunItemFields[itemType] ?? [])
    .filter((field) => !required.includes(field))
    .map((field) => `${relativeFile}: ${itemType} must require ${field}`);
}

const closedTaggedUnionPaths = [
  ["definitions", "runItem", "oneOf"],
  ["definitions", "workflowContinuation", "oneOf"],
  ["definitions", "operatorDecision", "oneOf"],
];

function checkClosedTaggedUnionBranches(relativeFile, schema) {
  return closedTaggedUnionPaths.flatMap((unionPath) =>
    closedTaggedUnionErrors(relativeFile, schema, unionPath),
  );
}

function closedTaggedUnionErrors(relativeFile, schema, unionPath) {
  const branches = schemaNode(schema, unionPath);
  if (!Array.isArray(branches)) {
    return [`${relativeFile}: missing tagged union ${unionPath.join(".")}`];
  }
  return branches.flatMap((branch) => closedTaggedBranchError(relativeFile, schema, branch));
}

function closedTaggedBranchError(relativeFile, schema, branch) {
  const definitionName = branch?.$ref?.replace("#/definitions/", "");
  const definition = definitionName && schemaNode(schema, ["definitions", definitionName]);
  return definition?.additionalProperties === false
    ? []
    : [
        `${relativeFile}: tagged branch ${definitionName ?? "<unknown>"} must reject unknown fields`,
      ];
}

function checkRunItemStructuralContract(relativeFile, schema) {
  if (relativeFile !== "schemas/run.items.schema.json") return [];
  const contractText = [
    schema.description,
    schema.$comment,
    schemaNode(schema, ["definitions", "safeText", "$comment"]),
    schemaNode(schema, ["definitions", "toolCallProgressItem", "$comment"]),
  ].join(" ");
  const requiredMarkers = [
    "structural",
    "RunItemPersistencePolicy",
    "SafeText",
    "completed <= total",
  ];
  return requiredMarkers
    .filter((marker) => !contractText.includes(marker))
    .map((marker) => `${relativeFile}: structural contract must name ${marker}`);
}

function checkProofLevelNumericBranch(relativeFile, schema) {
  void relativeFile;
  void schema;
  return [];
}

function schemaAcceptsObject(schema) {
  if (schema.type === "object") return true;
  return Array.isArray(schema.type) && schema.type.includes("object");
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function checkRequiredAliasGroups(relativeFile, schema) {
  return (requiredAliasGroupsBySchema[relativeFile] ?? []).flatMap((group) =>
    checkRequiredAliasGroup(relativeFile, schema, group),
  );
}

function checkRequiredAliasGroup(relativeFile, schema, group) {
  const node = schemaNode(schema, group.path);
  if (!isPlainObject(node))
    return [`${relativeFile}: missing alias schema node ${group.path.join(".")}`];
  return [
    aliasGroupIsRequired(node, group)
      ? null
      : `${relativeFile}: missing required alias group ${group.fields.join("/")}`,
    ...missingDeclaredAliasFields(relativeFile, node, group),
  ].filter(Boolean);
}

function aliasGroupIsRequired(schema, group) {
  return group.kind === "declared"
    ? true
    : group.kind === "required"
      ? group.fields.every((field) => requiredFields(schema).includes(field))
      : group.kind === "anyOf"
        ? anyOfRequiresFields(schema.anyOf, group.fields)
        : allOfContainsAnyOfRequirement(schema.allOf, group.fields);
}

function schemaNode(schema, nodePath) {
  return nodePath.reduce((node, segment) => {
    if (Array.isArray(node) && Number.isInteger(segment)) return node[segment];
    return isPlainObject(node) ? node[segment] : undefined;
  }, schema);
}

function allOfContainsAnyOfRequirement(allOf, fields) {
  return Array.isArray(allOf) && allOf.some((entry) => anyOfRequiresFields(entry.anyOf, fields));
}

function anyOfRequiresFields(anyOf, fields) {
  return (
    Array.isArray(anyOf) &&
    fields.every((field) => anyOf.some((entry) => requiredFields(entry).includes(field)))
  );
}

function missingDeclaredAliasFields(relativeFile, schema, group) {
  if (!isPlainObject(schema.properties)) {
    return [`${relativeFile}: missing properties for alias group ${group.fields.join("/")}`];
  }
  return group.fields
    .filter((field) => !Object.hasOwn(schema.properties, field))
    .map((field) => `${relativeFile}: alias field ${field} is required but not declared`);
}

function requiredFields(schema) {
  return Array.isArray(schema?.required) ? schema.required : [];
}

function checkRoutePatterns(relativeFile, schema) {
  return (routePatternBySchema[relativeFile] ?? []).flatMap((nodePath) => {
    const node = schemaNode(schema, nodePath);
    return node?.pattern === "^(\\/|\\*)"
      ? []
      : [`${relativeFile}: missing route path pattern at ${nodePath.join(".")}`];
  });
}

function checkProofStateEnums(relativeFile, schema) {
  return (proofStateEnumBySchema[relativeFile] ?? []).flatMap((nodePath) => {
    const node = schemaNode(schema, nodePath);
    if (!Array.isArray(node?.enum))
      return [`${relativeFile}: missing proof-state enum at ${nodePath.join(".")}`];
    return missingEntries(expectedProofStates, node.enum, `${relativeFile}: missing proof-state`);
  });
}

function checkProofStateRefs(relativeFile, schema) {
  return (proofStateRefBySchema[relativeFile] ?? []).flatMap((nodePath) => {
    const node = schemaNode(schema, nodePath);
    return node?.$ref === "#/definitions/proofState"
      ? []
      : [`${relativeFile}: proof-state field must reference enum at ${nodePath.join(".")}`];
  });
}

function checkEnumValues(relativeFile, schema, spec) {
  const node = schemaNode(schema, spec.path);
  if (!Array.isArray(node?.enum))
    return [`${relativeFile}: missing ${spec.name} enum at ${spec.path.join(".")}`];
  return missingEntries(spec.values, node.enum, `${relativeFile}: missing ${spec.name}`);
}

function checkDefinitionRefs(relativeFile, schema, spec) {
  return spec.refs.flatMap((nodePath) => {
    const node = schemaNode(schema, nodePath);
    return node?.$ref === `#/definitions/${spec.name}`
      ? []
      : [`${relativeFile}: ${spec.name} field must reference enum at ${nodePath.join(".")}`];
  });
}

function checkNamedEnums(relativeFile, schema) {
  return (schemaEnumSpecs[relativeFile] ?? []).flatMap((spec) => [
    ...checkEnumValues(relativeFile, schema, spec),
    ...checkDefinitionRefs(relativeFile, schema, spec),
  ]);
}

function checkRunArtifactManifestReservedMetadata(relativeFile, schema) {
  if (relativeFile !== "schemas/run.artifacts.schema.json") return [];
  const rules = schemaNode(schema, ["definitions", "canonicalArtifactMetadata", "allOf"]);
  if (!Array.isArray(rules)) {
    return [`${relativeFile}: missing canonical artifact metadata rules`];
  }
  return reservedArtifactMetadataSpecs.flatMap((spec) => {
    const rule = rules.find((candidate) =>
      ruleMatchesPath(candidate, artifactPathPattern(spec.path)),
    );
    if (!rule) return [`${relativeFile}: missing reserved metadata rule for ${spec.path}`];
    return missingArtifactMetadataConsts(relativeFile, rule, spec);
  });
}

function checkRetiredArtifactMetadata(relativeFile, schema) {
  const retired = retiredArtifactMetadataSpecsBySchema[relativeFile] ?? [];
  if (retired.length === 0) return [];
  const rules = schemaNode(schema, ["definitions", "canonicalArtifactMetadata", "allOf"]);
  if (!Array.isArray(rules)) return [];
  return retired.flatMap((spec) => {
    const pathIsReserved = rules.some((rule) =>
      ruleMatchesPath(rule, artifactPathPattern(spec.path)),
    );
    const labelIsReserved = rules.some(
      (rule) => rule?.then?.properties?.label?.const === spec.label,
    );
    return pathIsReserved || labelIsReserved
      ? [`${relativeFile}: reserves retired artifact metadata for ${spec.path}`]
      : [];
  });
}

function ruleMatchesPath(rule, pattern) {
  return (
    requiredFields(rule?.if).includes("path") && rule?.if?.properties?.path?.pattern === pattern
  );
}

function missingArtifactMetadataConsts(relativeFile, rule, spec) {
  const properties = rule?.then?.properties;
  const expected = { label: spec.label, kind: spec.kind };
  return Object.entries(expected)
    .filter(([field, value]) => properties?.[field]?.const !== value)
    .map(([field]) => `${relativeFile}: reserved metadata rule for ${spec.path} must set ${field}`);
}

function artifactPathPattern(artifactPath) {
  return `(^|/)${artifactPath.replaceAll(".", "\\.")}$`;
}

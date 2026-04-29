import type { AgentRuntime } from "./agent-runtime/types.js";
import type {
  DfdFlow,
  DfdNode,
  StrideCategory,
  StrideThreat,
  ThreatModelDocument,
  TrustBoundary,
} from "./agents/tasks/threat-modeling/types.js";

export type ThreatPatchTarget = "element" | "flow" | "boundary" | "threat" | "metadata";
export type ThreatPatchOp = "add" | "update" | "remove";

export interface ThreatModelPatchOperation {
  op: ThreatPatchOp;
  target: ThreatPatchTarget;
  id?: string;
  matchName?: string;
  fields?: Record<string, unknown>;
  value?: unknown;
  reason: string;
}

export interface ThreatModelPatchProposal {
  instruction: string;
  summary: string;
  operations: ThreatModelPatchOperation[];
  diffLines: string[];
  validationErrors: string[];
  createdAt: number;
  source: "ai" | "heuristic";
  costUsd?: number;
}

const PATCH_JSON_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["summary", "operations"],
  properties: {
    summary: { type: "string" },
    operations: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["op", "target", "reason"],
        properties: {
          op: { type: "string", enum: ["add", "update", "remove"] },
          target: { type: "string", enum: ["element", "flow", "boundary", "threat", "metadata"] },
          id: { type: "string" },
          matchName: { type: "string" },
          fields: { type: "object", additionalProperties: true },
          value: { type: "object", additionalProperties: true },
          reason: { type: "string" },
        },
      },
    },
  },
} as const;

const STRIDE_ZERO: Record<StrideCategory, number> = {
  spoofing: 0,
  tampering: 0,
  repudiation: 0,
  "information-disclosure": 0,
  "denial-of-service": 0,
  "elevation-of-privilege": 0,
};

export async function proposeThreatModelPatch(input: {
  runtime: AgentRuntime;
  cwd: string;
  threatModel: ThreatModelDocument;
  instruction: string;
  signal?: AbortSignal;
}): Promise<ThreatModelPatchProposal> {
  const producedAt = Date.now();
  const prompt = buildPatchPrompt(input.threatModel, input.instruction);
  let structured: unknown;
  let costUsd = 0;
  let errorText: string | undefined;

  try {
    for await (const message of input.runtime.query({
      prompt,
      options: {
        cwd: input.cwd,
        model: "claude-haiku-4-5",
        effort: "low",
        thinkingDisabled: true,
        maxOutputTokens: 1600,
        outputFormat: {
          type: "json_schema",
          schema: PATCH_JSON_SCHEMA as unknown as Record<string, unknown>,
          strict: true,
          retryInvalidStructuredOutput: 1,
        },
      },
    })) {
      if (input.signal?.aborted) throw new Error("Patch proposal aborted");
      if (message.type !== "result") continue;
      structured = (message as { structuredOutput?: unknown }).structuredOutput;
      costUsd = (message as { totalCostUsd?: number }).totalCostUsd ?? 0;
      const errors = (message as { errors?: string[] }).errors;
      if (errors?.length) errorText = errors.join("; ");
    }
  } catch (err) {
    errorText = err instanceof Error ? err.message : String(err);
  }

  const proposal = parseStructuredProposal(input.instruction, structured, producedAt, costUsd);
  const finalProposal =
    proposal ?? createHeuristicPatch(input.threatModel, input.instruction, producedAt);
  const validationErrors = validateThreatModelPatch(input.threatModel, finalProposal.operations);
  const diffLines = buildThreatModelPatchDiff(input.threatModel, finalProposal.operations);
  return {
    ...finalProposal,
    diffLines,
    validationErrors: errorText
      ? [...validationErrors, `AI proposal note: ${errorText}`]
      : validationErrors,
  };
}

export function applyThreatModelPatch(
  doc: ThreatModelDocument,
  proposal: ThreatModelPatchProposal,
  now: Date = new Date(),
): { ok: true; document: ThreatModelDocument } | { ok: false; errors: string[] } {
  const errors = validateThreatModelPatch(doc, proposal.operations);
  if (errors.length > 0) return { ok: false, errors };

  const next = cloneDocument(doc);
  normalizeDfdShape(next);
  for (const operation of proposal.operations) {
    applyOperation(next, operation);
  }
  normalizeBoundaryCrossings(next);
  syncLegacyDfdShape(next);
  next.summary = recomputeSummary(next.threats);
  next.userEdited = true;
  next.lastEditedAt = now.toISOString();
  return { ok: true, document: next };
}

export function validateThreatModelPatch(
  doc: ThreatModelDocument,
  operations: ReadonlyArray<ThreatModelPatchOperation>,
): string[] {
  const errors: string[] = [];
  const normalized = cloneDocument(doc);
  normalizeDfdShape(normalized);
  const elementIds = new Set(normalized.dfd.nodes.map((element) => element.id));
  const flowIds = new Set(normalized.dfd.flows.map((flow) => flow.id));
  const boundaryIds = new Set(normalized.dfd.trustBoundaries.map((boundary) => boundary.id));
  const threatIds = new Set(normalized.threats.map((threat) => threat.id));

  for (const operation of operations) {
    if (operation.op === "add") {
      const value = operation.value as Record<string, unknown> | undefined;
      const id = typeof value?.["id"] === "string" ? value["id"] : operation.id;
      if (!id) errors.push(`${operation.target} add is missing id`);
      if (operation.target === "element") {
        if (id && elementIds.has(id)) errors.push(`DFD node already exists: ${id}`);
      }
      if (operation.target === "flow") {
        if (id && flowIds.has(id)) errors.push(`DFD flow already exists: ${id}`);
      }
      if (operation.target === "boundary" && id && boundaryIds.has(id)) {
        errors.push(`Trust boundary already exists: ${id}`);
      }
      if (operation.target === "threat" && id && threatIds.has(id)) {
        errors.push(`Threat already exists: ${id}`);
      }
      continue;
    }

    const resolved = resolveOperationId(normalized, operation);
    if (!resolved && operation.target !== "metadata") {
      errors.push(
        `${operation.op} ${operation.target} could not resolve ${operation.id ?? operation.matchName ?? "(missing id)"}`,
      );
      continue;
    }
    if (operation.target === "flow") {
      const flow = normalized.dfd.flows.find((candidate) => candidate.id === resolved);
      if (!flow) errors.push(`${resolved} is not a data-flow`);
    }
  }

  const simulated = cloneDocument(normalized);
  for (const operation of operations) {
    if (!errors.length) applyOperation(simulated, operation);
  }
  normalizeBoundaryCrossings(simulated);
  const ids = new Set(simulated.dfd.nodes.map((element) => element.id));
  const simulatedFlowIds = new Set(simulated.dfd.flows.map((flow) => flow.id));
  for (const flow of simulated.dfd.flows) {
    if (!ids.has(flow.sourceId)) errors.push(`Flow ${flow.id} has missing source ${flow.sourceId}`);
    if (!ids.has(flow.targetId)) errors.push(`Flow ${flow.id} has missing target ${flow.targetId}`);
  }
  for (const boundary of simulated.dfd.trustBoundaries) {
    for (const flowId of boundary.crossingFlowIds) {
      if (!simulatedFlowIds.has(flowId)) {
        errors.push(`Boundary ${boundary.id} references missing flow ${flowId}`);
      }
    }
  }
  return [...new Set(errors)];
}

function buildPatchPrompt(doc: ThreatModelDocument, instruction: string): string {
  const normalized = cloneDocument(doc);
  normalizeDfdShape(normalized);
  const compact = {
    nodes: normalized.dfd.nodes.map((element) => ({
      id: element.id,
      type: element.type,
      name: element.name,
      trustZone: element.trustZone,
    })),
    flows: normalized.dfd.flows.map((flow) => ({
      id: flow.id,
      name: flow.name,
      sourceId: flow.sourceId,
      targetId: flow.targetId,
      protocol: flow.protocol,
    })),
    trustBoundaries: normalized.dfd.trustBoundaries.map((boundary) => ({
      id: boundary.id,
      name: boundary.name,
      innerZone: boundary.innerZone,
      outerZone: boundary.outerZone,
      crossingFlowIds: boundary.crossingFlowIds,
    })),
    threats: normalized.threats.map((threat) => ({
      id: threat.id,
      targetElementIds: threat.targetElementIds,
      actorIds: threat.actorIds,
      flowIds: threat.flowIds,
      category: threat.category,
      title: threat.title,
    })),
  };
  return [
    "You propose safe, reviewable patches to a cybersecurity threat-model JSON document.",
    "Never apply changes directly. Return only a structured patch.",
    "",
    "Allowed targets:",
    "- element: DFD node (external-entity, process, or data-store)",
    "- flow: DFD flow with sourceId and targetId",
    "- boundary: trust boundary",
    "- threat: STRIDE threat",
    "- metadata: small document metadata updates",
    "",
    "Rules:",
    "1. Prefer remove/update operations over replacing the whole model.",
    "2. Preserve unrelated nodes, flows, threats, and operator annotations.",
    "3. When removing an element, connected flows may also be removed.",
    "4. Use id when known; use matchName when the user names a thing.",
    "",
    `Operator instruction: ${instruction}`,
    "",
    "Current model:",
    JSON.stringify(compact, null, 2),
  ].join("\n");
}

function parseStructuredProposal(
  instruction: string,
  structured: unknown,
  createdAt: number,
  costUsd: number,
): ThreatModelPatchProposal | null {
  if (!structured || typeof structured !== "object" || Array.isArray(structured)) return null;
  const raw = structured as Record<string, unknown>;
  const operations = Array.isArray(raw["operations"])
    ? raw["operations"].flatMap((entry) => normalizeOperation(entry))
    : [];
  return {
    instruction,
    summary:
      typeof raw["summary"] === "string" ? raw["summary"] : "AI proposed threat-model edits.",
    operations,
    diffLines: [],
    validationErrors: [],
    createdAt,
    source: "ai",
    costUsd,
  };
}

function normalizeOperation(entry: unknown): ThreatModelPatchOperation[] {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
  const raw = entry as Record<string, unknown>;
  const op = raw["op"];
  const target = raw["target"];
  if (op !== "add" && op !== "update" && op !== "remove") return [];
  if (
    target !== "element" &&
    target !== "flow" &&
    target !== "boundary" &&
    target !== "threat" &&
    target !== "metadata"
  ) {
    return [];
  }
  return [
    {
      op,
      target,
      ...(typeof raw["id"] === "string" ? { id: raw["id"] } : {}),
      ...(typeof raw["matchName"] === "string" ? { matchName: raw["matchName"] } : {}),
      ...(isRecord(raw["fields"]) ? { fields: raw["fields"] } : {}),
      ...(isRecord(raw["value"]) ? { value: raw["value"] } : {}),
      reason: typeof raw["reason"] === "string" ? raw["reason"] : "operator requested change",
    },
  ];
}

function createHeuristicPatch(
  doc: ThreatModelDocument,
  instruction: string,
  createdAt: number,
): ThreatModelPatchProposal {
  const normalized = cloneDocument(doc);
  normalizeDfdShape(normalized);
  const removeMatch = instruction.match(/\bremove\s+(?:the\s+)?(.+?)(?:\s+from\b|$)/i);
  const name = removeMatch?.[1]?.trim().replace(/^["']|["']$/g, "");
  const element = name
    ? (normalized.dfd.nodes.find(
        (candidate) => candidate.name.toLowerCase() === name.toLowerCase(),
      ) ??
      normalized.dfd.nodes.find((candidate) =>
        candidate.name.toLowerCase().includes(name.toLowerCase()),
      ))
    : undefined;
  const operations: ThreatModelPatchOperation[] = element
    ? [
        {
          op: "remove",
          target: "element",
          id: element.id,
          matchName: element.name,
          reason: `Remove ${element.name} and connected flows.`,
        },
      ]
    : [];
  return {
    instruction,
    summary: element ? `Remove ${element.name} from the DFD.` : "No safe heuristic patch found.",
    operations,
    diffLines: [],
    validationErrors: operations.length === 0 ? ["No matching DFD element found."] : [],
    createdAt,
    source: "heuristic",
  };
}

function buildThreatModelPatchDiff(
  doc: ThreatModelDocument,
  operations: ReadonlyArray<ThreatModelPatchOperation>,
): string[] {
  const normalized = cloneDocument(doc);
  normalizeDfdShape(normalized);
  const lines: string[] = [];
  for (const operation of operations) {
    const id =
      resolveOperationId(normalized, operation) ?? operation.id ?? operation.matchName ?? "(new)";
    if (operation.op === "remove" && operation.target === "element") {
      const element = normalized.dfd.nodes.find((candidate) => candidate.id === id);
      if (!element) continue;
      lines.push(`- ${element.id} ${element.name}`);
      const connected = normalized.dfd.flows.filter(
        (candidate) => candidate.sourceId === element.id || candidate.targetId === element.id,
      );
      for (const flow of connected) lines.push(`- ${flow.id} ${flow.sourceId} -> ${flow.targetId}`);
      continue;
    }
    const sign = operation.op === "add" ? "+" : operation.op === "remove" ? "-" : "~";
    lines.push(`${sign} ${operation.target} ${id}`);
  }
  return lines.length > 0 ? lines : ["(no visible diff)"];
}

function applyOperation(doc: ThreatModelDocument, operation: ThreatModelPatchOperation): void {
  const id = resolveOperationId(doc, operation) ?? operation.id;
  if (operation.op === "remove") {
    if (operation.target === "element" && id) {
      doc.dfd.nodes = doc.dfd.nodes.filter((element) => element.id !== id);
      doc.dfd.flows = doc.dfd.flows.filter((flow) => flow.sourceId !== id && flow.targetId !== id);
      doc.threats = doc.threats.filter(
        (threat) => !(threat.targetElementIds ?? []).includes(id) && threat.elementId !== id,
      );
    } else if (operation.target === "flow" && id) {
      doc.dfd.flows = doc.dfd.flows.filter((flow) => flow.id !== id);
    } else if (operation.target === "boundary" && id) {
      doc.dfd.trustBoundaries = doc.dfd.trustBoundaries.filter((boundary) => boundary.id !== id);
    } else if (operation.target === "threat" && id) {
      doc.threats = doc.threats.filter((threat) => threat.id !== id);
    }
    return;
  }

  if (operation.op === "update" && id) {
    const fields = operation.fields ?? {};
    if (operation.target === "element") {
      const element = doc.dfd.nodes.find((candidate) => candidate.id === id);
      if (element) Object.assign(element, fields);
    } else if (operation.target === "flow") {
      const flow = doc.dfd.flows.find((candidate) => candidate.id === id);
      if (flow) Object.assign(flow, normalizeFlowPatchFields(fields));
    } else if (operation.target === "boundary") {
      const boundary = doc.dfd.trustBoundaries.find((candidate) => candidate.id === id);
      if (boundary) Object.assign(boundary, fields);
    } else if (operation.target === "threat") {
      const threat = doc.threats.find((candidate) => candidate.id === id);
      if (threat) Object.assign(threat, fields);
    }
    return;
  }

  if (operation.op === "add") {
    if (operation.target === "element") {
      doc.dfd.nodes.push(operation.value as DfdNode);
    } else if (operation.target === "flow") {
      doc.dfd.flows.push(operation.value as DfdFlow);
    } else if (operation.target === "boundary") {
      doc.dfd.trustBoundaries.push(operation.value as TrustBoundary);
    } else if (operation.target === "threat") {
      doc.threats.push(operation.value as StrideThreat);
    }
  }
}

function resolveOperationId(
  doc: ThreatModelDocument,
  operation: ThreatModelPatchOperation,
): string | undefined {
  if (operation.id) return operation.id;
  if (!operation.matchName) return undefined;
  const needle = operation.matchName.toLowerCase();
  if (operation.target === "boundary") {
    return doc.dfd.trustBoundaries.find((boundary) => boundary.name.toLowerCase() === needle)?.id;
  }
  if (operation.target === "threat") {
    return doc.threats.find((threat) => threat.title.toLowerCase() === needle)?.id;
  }
  if (operation.target === "flow") {
    return doc.dfd.flows.find((flow) => flow.name?.toLowerCase() === needle)?.id;
  }
  return doc.dfd.nodes.find((element) => element.name.toLowerCase() === needle)?.id;
}

function normalizeBoundaryCrossings(doc: ThreatModelDocument): void {
  const flowIds = new Set(doc.dfd.flows.map((flow) => flow.id));
  for (const boundary of doc.dfd.trustBoundaries) {
    boundary.crossingFlowIds = boundary.crossingFlowIds.filter((flowId) => flowIds.has(flowId));
  }
}

function normalizeDfdShape(doc: ThreatModelDocument): void {
  const dfd = doc.dfd as {
    nodes?: DfdNode[];
    flows?: DfdFlow[];
    elements?: Array<Record<string, unknown>>;
    trustBoundaries?: Array<TrustBoundary & { crossingFlows?: string[] }>;
  };
  const legacyElements = Array.isArray(dfd.elements) ? dfd.elements : [];
  if (!Array.isArray(dfd.nodes)) {
    dfd.nodes = legacyElements
      .filter((element) => element["type"] !== "data-flow")
      .map((element) => element as unknown as DfdNode);
  }
  if (!Array.isArray(dfd.flows)) {
    dfd.flows = legacyElements
      .filter((element) => element["type"] === "data-flow")
      .map((element) => ({
        id: String(element["id"] ?? ""),
        name: typeof element["name"] === "string" ? element["name"] : undefined,
        description: String(element["description"] ?? element["name"] ?? ""),
        sourceId: String(element["sourceId"] ?? element["source_id"] ?? element["source"] ?? ""),
        targetId: String(element["targetId"] ?? element["target_id"] ?? element["target"] ?? ""),
        trustBoundaryIds: Array.isArray(element["trustBoundaryIds"])
          ? (element["trustBoundaryIds"] as string[])
          : [],
      }))
      .filter((flow) => flow.id && flow.sourceId && flow.targetId);
  }
  dfd.trustBoundaries = (dfd.trustBoundaries ?? []).map((boundary) => ({
    ...boundary,
    crossingFlowIds: boundary.crossingFlowIds ?? boundary.crossingFlows ?? [],
  }));
}

function syncLegacyDfdShape(doc: ThreatModelDocument): void {
  if (!("elements" in doc.dfd)) return;
  const elements: Array<Record<string, unknown>> = [
    ...doc.dfd.nodes.map((node) => ({ ...node }) as Record<string, unknown>),
    ...doc.dfd.flows.map(
      (flow) =>
        ({
          ...flow,
          type: "data-flow",
          source: flow.sourceId,
          target: flow.targetId,
        }) as Record<string, unknown>,
    ),
  ];
  (doc.dfd as unknown as { elements: Array<Record<string, unknown>> }).elements = elements;
  for (const boundary of doc.dfd.trustBoundaries as Array<
    TrustBoundary & { crossingFlows?: string[] }
  >) {
    if ("crossingFlows" in boundary) boundary.crossingFlows = boundary.crossingFlowIds;
  }
}

function normalizeFlowPatchFields(fields: Record<string, unknown>): Record<string, unknown> {
  const out = { ...fields };
  if ("source" in out && !("sourceId" in out)) {
    out["sourceId"] = out["source"];
    delete out["source"];
  }
  if ("target" in out && !("targetId" in out)) {
    out["targetId"] = out["target"];
    delete out["target"];
  }
  return out;
}

function recomputeSummary(threats: StrideThreat[]): ThreatModelDocument["summary"] {
  const bySeverity: Record<string, number> = {};
  const byCategory = { ...STRIDE_ZERO };
  for (const threat of threats) {
    bySeverity[threat.impact] = (bySeverity[threat.impact] ?? 0) + 1;
    byCategory[threat.category] = (byCategory[threat.category] ?? 0) + 1;
  }
  return { total: threats.length, bySeverity, byCategory };
}

function cloneDocument(doc: ThreatModelDocument): ThreatModelDocument {
  return JSON.parse(JSON.stringify(doc)) as ThreatModelDocument;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

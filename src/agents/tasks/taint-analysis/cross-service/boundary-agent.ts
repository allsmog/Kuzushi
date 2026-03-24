import path from "node:path";
import type { AgentRuntime } from "../../../../agent-runtime/types.js";
import type {
  AgentResultErrorMessage,
  AgentResultSuccessMessage,
  AgentToolDecision,
} from "../../../../agent-runtime/types.js";
import { attachTaskOutputMeta } from "../../../../task-output-meta.js";
import { isRecord, toErrorMessage } from "../../../../utils.js";
import {
  BOUNDARY_RESPONSE_SCHEMA,
  type BoundaryManifest,
  type BoundaryPoint,
  type BoundaryDirection,
  type BoundaryProtocol,
  type ServiceDescriptor,
} from "./types.js";

const MAX_RETRIES = 1;

interface BoundaryAgentOptions {
  service: ServiceDescriptor;
  repoRoot: string;
  model: string;
  confidenceThreshold: number;
  runtime: AgentRuntime;
}

interface BoundaryAgentRawResponse {
  entryPoints: BoundaryPoint[];
  exitPoints: BoundaryPoint[];
}

/**
 * Runs an LLM agent to detect entry/exit boundary points for a service.
 * Uses Read/Glob/Grep tools restricted to the service subdirectory.
 */
export async function detectServiceBoundaries(
  options: BoundaryAgentOptions,
): Promise<BoundaryManifest> {
  const { service, repoRoot, model, confidenceThreshold, runtime } = options;
  const serviceRoot = path.resolve(repoRoot, service.rootPath);
  const canUseTool = createBoundaryToolGuard(serviceRoot);
  const prompt = buildBoundaryPrompt(service);

  let resultText = "";
  let structuredOutput: unknown;
  let executionError: string | null = null;
  let costUsd = 0;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    resultText = "";
    structuredOutput = undefined;
    executionError = null;

    try {
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: serviceRoot,
          model,
          maxTurns: 15,
          allowedTools: ["Read", "Glob", "Grep"],
          permissionMode: "dontAsk",
          canUseTool,
          outputFormat: {
            type: "json_schema",
            schema: BOUNDARY_RESPONSE_SCHEMA as unknown as Record<string, unknown>,
            strict: true,
            retryInvalidStructuredOutput: 2,
          },
        },
      })) {
        if (message.type !== "result") continue;

        if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
          costUsd = message.totalCostUsd;
        }

        if (message.subtype === "success") {
          const success = message as AgentResultSuccessMessage;
          resultText = success.result;
          structuredOutput = success.structuredOutput;
        } else {
          const errMsg = (message as AgentResultErrorMessage).errors.join("; ") || message.subtype;
          executionError = errMsg;
        }
      }
    } catch (error) {
      executionError = toErrorMessage(error);
      if (attempt < MAX_RETRIES) continue;
    }

    if (structuredOutput || resultText) break;
    if (executionError && attempt >= MAX_RETRIES) break;
  }

  if (executionError && !structuredOutput && !resultText) {
    throw withCost(
      new Error(`Boundary detection error: ${executionError}`),
      costUsd,
    );
  }

  const errors: string[] = [];
  if (executionError) {
    errors.push(`Boundary detection error: ${executionError}`);
  }

  let parsed: BoundaryAgentRawResponse;
  try {
    parsed = parseBoundaryResponse(structuredOutput ?? resultText, confidenceThreshold);
  } catch (error) {
    throw withCost(
      new Error(`Boundary detection response parse failed: ${toErrorMessage(error)}`),
      costUsd,
    );
  }

  return attachTaskOutputMeta({
    serviceId: service.id,
    servicePath: service.rootPath,
    entryPoints: parsed.entryPoints,
    exitPoints: parsed.exitPoints,
    errors,
  }, { costUsd });
}

// ── Prompt ───────────────────────────────────────────────────────────────

function buildBoundaryPrompt(service: ServiceDescriptor): string {
  const lines = [
    `You are a service boundary detection agent analyzing the "${service.displayName}" service.`,
    "",
    "## Service context",
    `- Language: ${service.language}`,
    `- Framework: ${service.framework ?? "unknown"}`,
    `- Root path: ${service.rootPath}`,
    "",
    "## Your task",
    "Identify all **entry points** (how external traffic enters this service) and **exit points** (how this service calls other services or external systems).",
    "",
    "### Entry points to look for:",
    "- HTTP route handlers (REST endpoints, middleware-registered routes)",
    "- gRPC server method implementations",
    "- Message queue consumers (Kafka, RabbitMQ, SQS, etc.)",
    "- Event listeners (EventEmitter, pub/sub handlers)",
    "- Scheduled job handlers that process external data",
    "",
    "### Exit points to look for:",
    "- HTTP client calls (fetch, axios, http.Client, requests, etc.)",
    "- gRPC client stubs and calls",
    "- Message queue publishers (producing messages to topics/queues)",
    "- Event emitters that send data to other services",
    "- Direct database writes that are read by other services (shared DB pattern)",
    "",
    "## Instructions",
    "1. Use Glob to discover relevant source files (routes, handlers, controllers, clients, producers).",
    "2. Use Read/Grep to inspect the discovered files and identify boundary points.",
    "3. For each boundary point, determine:",
    "   - The protocol type (http-server, http-client, grpc-server, grpc-client, message-publish, message-consume, database-write, database-read, event-emit, event-listen)",
    "   - The file path and line number",
    "   - The callable name (function/method name)",
    "   - Route path (for HTTP), topic/queue name (for messaging), gRPC method name",
    "   - What data flows through the boundary (tainted parameters)",
    "   - Confidence (0-1) based on how certain you are this is a real boundary point",
    "",
    "## Output format",
    "Return JSON with `entryPoints` and `exitPoints` arrays. Each point needs a unique `id` (e.g., `entry-1`, `exit-1`).",
    "Set `direction` to `entry` for entry points and `exit` for exit points.",
    "",
    "## Important",
    "- Only include boundary points you are confident about (confidence >= 0.3).",
    "- Focus on user-facing or inter-service boundaries, not internal function calls.",
    "- Include the `dataDescription` field with a brief note about what data flows through.",
    "- Include `taintedParameters` listing parameter names that carry user/external data.",
  ];

  return lines.join("\n");
}

// ── Tool Guard ──────────────────────────────────────────────────────────

function createBoundaryToolGuard(serviceRoot: string) {
  const resolvedRoot = path.resolve(serviceRoot);

  return (toolName: string, args: Record<string, unknown>): AgentToolDecision => {
    if (toolName === "Read" || toolName === "Glob" || toolName === "Grep") {
      const inputPath = getPathArg(args);
      if (!inputPath) return { behavior: "allow" };

      const resolved = path.isAbsolute(inputPath)
        ? path.normalize(inputPath)
        : path.resolve(resolvedRoot, inputPath);

      if (!isWithinRoot(resolvedRoot, resolved)) {
        return {
          behavior: "deny",
          message: `Path must stay inside service root: ${serviceRoot}`,
        };
      }

      return { behavior: "allow" };
    }

    return {
      behavior: "deny",
      message: `Tool "${toolName}" is not allowed in boundary detection`,
    };
  };
}

// ── Response Parsing ────────────────────────────────────────────────────

function parseBoundaryResponse(
  value: unknown,
  confidenceThreshold: number,
): BoundaryAgentRawResponse {
  if (isRecord(value)) {
    return {
      entryPoints: parsePointArray(value["entryPoints"], "entry", confidenceThreshold),
      exitPoints: parsePointArray(value["exitPoints"], "exit", confidenceThreshold),
    };
  }

  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(extractJson(value));
      return parseBoundaryResponse(parsed, confidenceThreshold);
    } catch (error) {
      throw new Error(`Could not parse boundary detection JSON: ${toErrorMessage(error)}`);
    }
  }

  throw new Error("Unexpected boundary detection response shape");
}

function withCost<T extends Error>(error: T, costUsd: number): T & { costUsd: number } {
  return Object.assign(error, { costUsd });
}

function parsePointArray(
  value: unknown,
  expectedDirection: BoundaryDirection,
  confidenceThreshold: number,
): BoundaryPoint[] {
  if (!Array.isArray(value)) return [];

  return value
    .map((item, index) => normalizePoint(item, expectedDirection, index))
    .filter((point): point is BoundaryPoint => point !== null && point.confidence >= confidenceThreshold);
}

function normalizePoint(
  value: unknown,
  expectedDirection: BoundaryDirection,
  index: number,
): BoundaryPoint | null {
  if (!isRecord(value)) return null;

  const id = asString(value["id"]) || `${expectedDirection}-${index + 1}`;
  const protocol = asProtocol(value["protocol"]);
  const filePath = asString(value["filePath"]);
  const startLine = asPositiveInt(value["startLine"]);
  const callable = asString(value["callable"]);
  const dataDescription = asString(value["dataDescription"]);
  const confidence = asUnitNumber(value["confidence"]);
  const rationale = asString(value["rationale"]);

  if (!filePath || !callable) return null;

  return {
    id,
    direction: expectedDirection,
    protocol,
    filePath,
    startLine: startLine || 1,
    callable,
    routePath: asOptionalString(value["routePath"]),
    httpMethod: asOptionalString(value["httpMethod"]),
    topicOrQueue: asOptionalString(value["topicOrQueue"]),
    grpcMethod: asOptionalString(value["grpcMethod"]),
    dataEntity: asOptionalString(value["dataEntity"]),
    dataDescription: dataDescription || "data",
    taintedParameters: asStringArray(value["taintedParameters"]),
    confidence,
    rationale: rationale || "Detected by boundary agent",
  };
}

// ── Helpers ─────────────────────────────────────────────────────────────

function getPathArg(args: Record<string, unknown>): string | null {
  for (const key of ["path", "file_path", "filePath", "pattern"]) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

function isWithinRoot(rootPath: string, candidatePath: string): boolean {
  const relative = path.relative(path.resolve(rootPath), path.resolve(candidatePath));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function extractJson(value: string): string {
  const fenced = value.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenced) return fenced[1].trim();
  const first = value.indexOf("{");
  const last = value.lastIndexOf("}");
  if (first >= 0 && last > first) return value.slice(first, last + 1);
  return value;
}

const VALID_PROTOCOLS = new Set<BoundaryProtocol>([
  "http-server", "http-client",
  "grpc-server", "grpc-client",
  "message-publish", "message-consume",
  "database-write", "database-read",
  "event-emit", "event-listen",
  "unknown",
]);

function asProtocol(value: unknown): BoundaryProtocol {
  const str = typeof value === "string" ? value.trim().toLowerCase() : "";
  return VALID_PROTOCOLS.has(str as BoundaryProtocol) ? (str as BoundaryProtocol) : "unknown";
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function asOptionalString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function asPositiveInt(value: unknown): number {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 1 ? Math.floor(numeric) : 0;
}

function asUnitNumber(value: unknown): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(1, numeric));
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => String(item).trim()).filter(Boolean);
}

export const __boundaryAgentInternals = {
  buildBoundaryPrompt,
  parseBoundaryResponse,
  createBoundaryToolGuard,
  normalizePoint,
};

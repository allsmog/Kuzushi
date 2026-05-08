import { Type } from "@mariozechner/pi-ai";
import type { AgentRuntimeTool } from "../../agent-runtime/types.js";
import { searchThreatModelKb, type ThreatModelKbSearchInput } from "../threat-model/kb-index.js";

export const THREAT_KB_SEARCH_TOOL = "ThreatKbSearch";

const ThreatKbSearchParameters = Type.Object(
  {
    query: Type.Optional(
      Type.String({
        description:
          "Text query for threat-model details, evidence, source/sink hints, guards, or mitigations.",
      }),
    ),
    actorId: Type.Optional(Type.String({ description: "Filter results to one DFD actor id." })),
    flowIds: Type.Optional(
      Type.Array(Type.String(), { description: "Filter results to linked DFD flow ids." }),
    ),
    threatIds: Type.Optional(
      Type.Array(Type.String(), { description: "Filter results to specific threat ids." }),
    ),
    kinds: Type.Optional(
      Type.Array(Type.String(), {
        description:
          "Optional chunk kind filters, e.g. threat, flow, evidence, source, sink, guard, sanitizer.",
      }),
    ),
    limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 50 })),
  },
  { additionalProperties: true },
);

export function createThreatKbSearchTool(options: {
  kbPath: string;
  defaultLimit: number;
  maxChunkChars: number;
}): AgentRuntimeTool {
  return {
    name: THREAT_KB_SEARCH_TOOL,
    description:
      "Search the reusable threat-model knowledge base for Randori graph details, linked threats, evidence anchors, source/sink hints, guards, sanitizers, and required capabilities.",
    parameters: ThreatKbSearchParameters,
    execute(input) {
      const normalized = normalizeInput(input, options.defaultLimit, options.maxChunkChars);
      const result = searchThreatModelKb(options.kbPath, normalized);
      return JSON.stringify(
        {
          kbPath: result.path,
          query: result.query,
          count: result.results.length,
          results: result.results,
        },
        null,
        2,
      );
    },
  };
}

function normalizeInput(
  input: Record<string, unknown>,
  defaultLimit: number,
  maxChunkChars: number,
): ThreatModelKbSearchInput {
  return {
    query: stringOrUndefined(input["query"]),
    actorId: stringOrUndefined(input["actorId"] ?? input["actor_id"]),
    flowIds: stringArray(input["flowIds"] ?? input["flow_ids"]),
    threatIds: stringArray(input["threatIds"] ?? input["threat_ids"]),
    kinds: stringArray(input["kinds"] ?? input["kind"]),
    limit: numberOrDefault(input["limit"], defaultLimit),
    maxChunkChars,
  };
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function stringArray(value: unknown): string[] | undefined {
  if (typeof value === "string" && value.trim()) return [value.trim()];
  if (!Array.isArray(value)) return undefined;
  const out = value.filter(
    (item): item is string => typeof item === "string" && item.trim() !== "",
  );
  return out.length > 0 ? out : undefined;
}

function numberOrDefault(value: unknown, fallback: number): number {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

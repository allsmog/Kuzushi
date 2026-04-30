import { createLogger } from "../../../logger.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { DagNodeImpl } from "../../types.js";
import { resolveTaskAllowedTools } from "../runtime-overrides.js";
import { formatSystemsHuntProfileLines, formatSystemsSurfacePack } from "./helpers.js";
import type {
  RankedSystemsSurface,
  SystemsContextOutput,
  SystemsInvariant,
  SystemsInvariantKind,
  SystemsInvariantOutput,
  SystemsSurfacePack,
} from "./types.js";
import { resolveSystemsHuntConfig } from "./types.js";

const log = createLogger({ stage: "systems-invariant-extract" });

const INVARIANT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["invariants"],
  properties: {
    invariants: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "id",
          "surfaceId",
          "kind",
          "summary",
          "statement",
          "rationale",
          "evidence",
          "attackerControlledFields",
          "cheapVerifiable",
        ],
        properties: {
          id: { type: "string" },
          surfaceId: { type: "string" },
          kind: {
            type: "string",
            enum: [
              "state-transition",
              "packet-ordering",
              "sentinel-boundary",
              "counter-upper-bound",
              "length-buffer-coupling",
              "resource-provenance",
              "aliasing-boundary",
              "failure-side-effect",
              "unsafe-precondition",
            ],
          },
          summary: { type: "string" },
          statement: { type: "string" },
          rationale: { type: "string" },
          evidence: { type: "array", items: { type: "string" } },
          attackerControlledFields: { type: "array", items: { type: "string" } },
          cheapVerifiable: { type: "boolean" },
        },
      },
    },
  },
} as const;

export const systemsInvariantExtractTask: DagNodeImpl<ScanOpts, SystemsInvariantOutput> = {
  id: "systems-invariant-extract",
  displayName: "Systems Invariant Extractor",
  outputKind: "custom",
  dependsOn: ["systems-context-gatherer"],

  condition(upstreamOutputs) {
    const output = upstreamOutputs.get("systems-context-gatherer") as
      | SystemsContextOutput
      | undefined;
    return (output?.surfaces.length ?? 0) > 0;
  },

  async run(_input, context): Promise<SystemsInvariantOutput> {
    const config = resolveSystemsHuntConfig(context);
    const surfaceOutput = context.upstreamOutputs.get("systems-context-gatherer") as
      | SystemsContextOutput
      | undefined;
    const surfaces = surfaceOutput?.surfaces.slice(0, config.maxSurfaces) ?? [];
    const packs = surfaceOutput?.surfacePacks ?? [];
    if (surfaces.length === 0) {
      return attachTaskOutputMeta({ invariants: [] }, { costUsd: 0 });
    }

    const prompt = buildInvariantPrompt(
      surfaces,
      packs,
      formatSystemsHuntProfileLines(context.securityProfiles),
    );
    let structuredOutput: unknown;
    let costUsd = 0;

    try {
      for await (const message of context.runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model: config.model,
          effort: config.effort,
          thinkingDisabled: config.thinkingDisabled,
          allowedTools: resolveTaskAllowedTools(context),
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: INVARIANT_SCHEMA,
            strict: true,
            retryInvalidStructuredOutput: 2,
          },
        },
      })) {
        if (message.type !== "result") continue;
        if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
          costUsd = message.totalCostUsd;
        }
        if ("result" in message) {
          structuredOutput = message.structuredOutput;
        }
      }
    } catch (error) {
      throw new Error(`[systems-invariant-extract] Agent error: ${toErrorMessage(error)}`);
    }

    const invariants = parseInvariants(structuredOutput);
    log.info(`Extracted ${invariants.length} systems invariants`);
    return attachTaskOutputMeta({ invariants }, { costUsd });
  },
};

export function buildInvariantPrompt(
  surfaces: RankedSystemsSurface[],
  packs: SystemsSurfacePack[] = [],
  profileLines: string[] = [],
): string {
  const packBySurfaceId = new Map(packs.map((pack) => [pack.surfaceId, pack]));
  const surfaceLines = surfaces.flatMap((surface, index) => [
    `### Surface ${index + 1}`,
    `surfaceId: ${surface.id}`,
    `Kind: ${surface.kind}`,
    `Location: ${surface.filePath}:${surface.startLine}`,
    `Reasons: ${surface.reasons.join("; ") || "none"}`,
    `Attacker-controlled fields: ${surface.attackerControlledFields.join(", ") || "unknown"}`,
    `Hardening signals: ${surface.hardeningSignals.join(", ") || "none"}`,
    `Evidence: ${
      surface.evidence
        .slice(0, 3)
        .map((signal) => `${signal.domain}@${signal.lineNumber}: ${signal.lineContent}`)
        .join(" | ") || "none"
    }`,
    ...formatSystemsSurfacePack(
      packBySurfaceId.get(surface.id) ?? {
        surfaceId: surface.id,
        anchorFilePath: surface.filePath,
        anchorStartLine: surface.startLine,
        relatedFiles: [surface.filePath],
        callers: [],
        callees: [],
        compareCastSites: [],
        counterSites: [],
        sentinelConstants: [],
        allocationCopySites: [],
        unsafeSites: [],
        resourceProvenanceSites: [],
        aliasingSites: [],
        scratchWriteSites: [],
        failureSideEffectSites: [],
        inputSites: [],
        hardeningSites: [],
        helperTemplates: [],
      },
    ),
    "",
  ]);

  return [
    "You are extracting security invariants for low-level systems code.",
    "For each ranked surface, derive the invariants that MUST hold for safety and exploit resistance.",
    "",
    "Focus on these invariant classes:",
    "- state-transition: allowed protocol or parser state transitions",
    "- packet-ordering: required ordering across sequential packets or options",
    "- sentinel-boundary: reserved sentinel values that must not collide with normal counters",
    "- counter-upper-bound: numeric bounds before indexing, allocation, or comparison",
    "- length-buffer-coupling: buffer size or stack/heap capacity must dominate copy length",
    "- resource-provenance: resource origin and backing-store identity must be preserved across zero-copy transfers",
    "- aliasing-boundary: writable aliases must not cross from caller-owned output into shared/read-only backing resources",
    "- failure-side-effect: validation or authentication failure paths must not preserve earlier mutations",
    "- unsafe-precondition: caller obligations before entering unsafe or raw-pointer code",
    "",
    ...(profileLines.length > 0 ? [...profileLines, ""] : []),
    "For resource-provenance surfaces, explicitly identify the resource origin, ownership boundary, aliasing transition, and whether failure paths leave mutations behind.",
    "",
    "Mark `cheapVerifiable=true` only when a single-turn bounded confirmation would likely be enough.",
    "Examples: a deterministic sentinel collision or a direct unsafe slice-length mismatch.",
    "",
    ...surfaceLines,
  ].join("\n");
}

export function parseInvariants(raw: unknown): SystemsInvariant[] {
  if (!isRecord(raw) || !Array.isArray(raw["invariants"])) return [];
  const out: SystemsInvariant[] = [];
  for (const item of raw["invariants"]) {
    if (!isRecord(item)) continue;
    const kind = normalizeInvariantKind(item["kind"]);
    const id = stringField(item["id"]);
    const surfaceId = stringField(item["surfaceId"]);
    const summary = stringField(item["summary"]);
    const statement = stringField(item["statement"]);
    const rationale = stringField(item["rationale"]);
    if (!id || !surfaceId || !summary || !statement || !rationale || !kind) continue;
    out.push({
      id,
      surfaceId,
      kind,
      summary,
      statement,
      rationale,
      evidence: stringArray(item["evidence"]),
      attackerControlledFields: stringArray(item["attackerControlledFields"]),
      cheapVerifiable: item["cheapVerifiable"] === true,
    });
  }
  return out;
}

function normalizeInvariantKind(value: unknown): SystemsInvariantKind | undefined {
  if (typeof value !== "string") return undefined;
  switch (value) {
    case "state-transition":
    case "packet-ordering":
    case "sentinel-boundary":
    case "counter-upper-bound":
    case "length-buffer-coupling":
    case "resource-provenance":
    case "aliasing-boundary":
    case "failure-side-effect":
    case "unsafe-precondition":
      return value;
    default:
      return undefined;
  }
}

function stringField(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => stringField(entry)).filter(Boolean);
}

export const __systemsInvariantExtractInternals = {
  buildInvariantPrompt,
  parseInvariants,
};

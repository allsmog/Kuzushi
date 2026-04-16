import { createLogger } from "../../../logger.js";
import { attachTaskOutputMeta } from "../../../task-output-meta.js";
import type { ScanOpts } from "../../../types.js";
import { isRecord, toErrorMessage } from "../../../utils.js";
import type { AgentTask } from "../../types.js";
import { resolveTaskAllowedTools } from "../runtime-overrides.js";
import { formatSystemsSurfacePack } from "./helpers.js";
import type {
  RankedSystemsSurface,
  SystemsContextOutput,
  SystemsInvariant,
  SystemsInvariantOutput,
  SystemsSurfacePack,
  SystemsTriggerHypothesis,
  SystemsTriggerOutput,
} from "./types.js";
import { resolveSystemsHuntConfig } from "./types.js";

const log = createLogger({ stage: "systems-trigger-synth" });

const TRIGGER_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["triggers"],
  properties: {
    triggers: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "id",
          "surfaceId",
          "orderedSteps",
          "boundaryAssignments",
          "statePreconditions",
          "attackerControlledFields",
          "expectedPrimitive",
          "cheapVerifiable",
          "rationale",
        ],
        properties: {
          id: { type: "string" },
          surfaceId: { type: "string" },
          orderedSteps: { type: "array", items: { type: "string" } },
          boundaryAssignments: {
            type: "object",
            additionalProperties: { type: "string" },
          },
          statePreconditions: { type: "array", items: { type: "string" } },
          attackerControlledFields: { type: "array", items: { type: "string" } },
          expectedPrimitive: { type: "string" },
          cheapVerifiable: { type: "boolean" },
          rationale: { type: "string" },
        },
      },
    },
  },
} as const;

export const systemsTriggerSynthTask: AgentTask<ScanOpts, SystemsTriggerOutput> = {
  id: "systems-trigger-synth",
  displayName: "Systems Trigger Synthesizer",
  outputKind: "custom",
  dependsOn: ["systems-invariant-extract"],

  condition(upstreamOutputs) {
    const output = upstreamOutputs.get("systems-context-gatherer") as
      | SystemsContextOutput
      | undefined;
    return (output?.surfaces.length ?? 0) > 0;
  },

  async run(_input, context): Promise<SystemsTriggerOutput> {
    const config = resolveSystemsHuntConfig(context);
    const surfaceOutput = context.upstreamOutputs.get("systems-context-gatherer") as
      | SystemsContextOutput
      | undefined;
    const invariantOutput = context.upstreamOutputs.get("systems-invariant-extract") as
      | SystemsInvariantOutput
      | undefined;
    const surfaces = surfaceOutput?.surfaces.slice(0, config.maxSurfaces) ?? [];
    const packs = surfaceOutput?.surfacePacks ?? [];
    if (surfaces.length === 0) {
      return attachTaskOutputMeta({ triggers: [] }, { costUsd: 0 });
    }

    const prompt = buildTriggerPrompt(
      surfaces,
      packs,
      invariantOutput?.invariants ?? [],
      config.maxTriggerHypothesesPerSurface,
    );
    let structuredOutput: unknown;
    let costUsd = 0;

    try {
      for await (const message of context.runtime.query({
        prompt,
        options: {
          cwd: context.repoRoot,
          model: config.model,
          allowedTools: resolveTaskAllowedTools(context),
          permissionMode: "dontAsk",
          outputFormat: {
            type: "json_schema",
            schema: TRIGGER_SCHEMA,
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
      throw new Error(`[systems-trigger-synth] Agent error: ${toErrorMessage(error)}`);
    }

    const triggers = parseTriggers(structuredOutput)
      .filter((trigger) => surfaces.some((surface) => surface.id === trigger.surfaceId))
      .slice(0, surfaces.length * config.maxTriggerHypothesesPerSurface);
    log.info(`Synthesized ${triggers.length} systems trigger hypotheses`);
    return attachTaskOutputMeta({ triggers }, { costUsd });
  },
};

export function buildTriggerPrompt(
  surfaces: RankedSystemsSurface[],
  packs: SystemsSurfacePack[],
  invariants: SystemsInvariant[],
  maxTriggerHypothesesPerSurface: number,
): string {
  const packBySurfaceId = new Map(packs.map((pack) => [pack.surfaceId, pack]));
  const invariantsBySurfaceId = new Map<string, SystemsInvariant[]>();
  for (const invariant of invariants) {
    const bucket = invariantsBySurfaceId.get(invariant.surfaceId) ?? [];
    bucket.push(invariant);
    invariantsBySurfaceId.set(invariant.surfaceId, bucket);
  }

  const sections = surfaces.flatMap((surface, index) => {
    const surfaceInvariants = invariantsBySurfaceId.get(surface.id) ?? [];
    const pack = packBySurfaceId.get(surface.id);
    return [
      `### Surface ${index + 1}`,
      `surfaceId: ${surface.id}`,
      `Kind: ${surface.kind}`,
      `Location: ${surface.filePath}:${surface.startLine}`,
      `Attacker-controlled fields: ${surface.attackerControlledFields.join(", ") || "unknown"}`,
      `Top invariants: ${surfaceInvariants.map((invariant) => `[${invariant.id}] ${invariant.summary}`).join(" | ") || "none"}`,
      ...(pack ? formatSystemsSurfacePack(pack) : []),
      "",
    ];
  });

  return [
    "You are synthesizing explicit trigger hypotheses for low-level systems-code bugs.",
    `Produce at most ${maxTriggerHypothesesPerSurface} trigger hypotheses per surface.`,
    "",
    "Each trigger hypothesis must describe a plausible attacker-controlled sequence, not just a local bug statement.",
    "Force explicit multi-step interactions when relevant: packet ordering, option interaction, frame sequencing, RPC auth exchanges, guest/host setup then misuse.",
    "Force explicit boundary assignments such as wraparound, -1, 0xffff, UINT_MAX, SIZE_MAX, truncation, sentinel collision, or oversized length fields.",
    "Only mark cheapVerifiable=true when a bounded local confirmation is realistically possible.",
    "",
    ...sections,
  ].join("\n");
}

export function parseTriggers(raw: unknown): SystemsTriggerHypothesis[] {
  if (!isRecord(raw) || !Array.isArray(raw["triggers"])) return [];
  const out: SystemsTriggerHypothesis[] = [];
  for (const item of raw["triggers"]) {
    if (!isRecord(item)) continue;
    const id = stringField(item["id"]);
    const surfaceId = stringField(item["surfaceId"]);
    const orderedSteps = stringArray(item["orderedSteps"]);
    const boundaryAssignments = stringRecord(item["boundaryAssignments"]);
    const statePreconditions = stringArray(item["statePreconditions"]);
    const attackerControlledFields = stringArray(item["attackerControlledFields"]);
    const expectedPrimitive = stringField(item["expectedPrimitive"]);
    const rationale = stringField(item["rationale"]);
    if (!id || !surfaceId || orderedSteps.length === 0 || !expectedPrimitive || !rationale)
      continue;
    out.push({
      id,
      surfaceId,
      orderedSteps,
      boundaryAssignments,
      statePreconditions,
      attackerControlledFields,
      expectedPrimitive,
      cheapVerifiable: item["cheapVerifiable"] === true,
      rationale,
    });
  }
  return out;
}

function stringField(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => stringField(entry)).filter(Boolean);
}

function stringRecord(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  const record: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    const normalized = stringField(entry);
    if (!normalized) continue;
    record[key] = normalized;
  }
  return record;
}

export const __systemsTriggerSynthInternals = {
  buildTriggerPrompt,
  parseTriggers,
};

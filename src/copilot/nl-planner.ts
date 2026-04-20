/**
 * Natural-language option planner.
 *
 * Operator types plain English at the shell prompt (e.g. "run harder, focus
 * on auth, stop wasting money"). This module asks a small, cheap Haiku call
 * to translate that intent into a structured diff against the focused
 * module's tool options. The shell renders the result as a PlanCard; `y`
 * applies the changes via the same path `/set` uses.
 *
 * Scope (v1):
 *   - Proposes changes only against the *tool-level* options exposed by the
 *     module's `inputSchema` (the same keys you'd see from `/options`).
 *   - Does not edit `~/.kuzushi/config.json` or module-global Datastore
 *     entries. Broader scope lives behind a revision loop in v2.
 *
 * Everything in this file is pure data + one well-isolated LLM call; the
 * shell owns state, apply, and rendering.
 */

import type { AgentRuntime } from "../agent-runtime/types.js";
import type { ModuleTool } from "../modules/types.js";

// ---------------------------------------------------------------------------
// Public types (also imported by the UI layer via state.ts).
// ---------------------------------------------------------------------------

/** One proposed change to a single option key. */
export interface ShellPlanChange {
  /** Option key as declared in the tool's inputSchema (e.g. "maxTurnsPerHunt"). */
  option: string;
  /**
   * The currently effective value, as JSON. `null` means the tool has no
   * override set and is running on its compiled default (shown as "default").
   */
  current: unknown;
  /** The value the planner wants to set. */
  proposed: unknown;
  /** One-line rationale — shown in the plan card "why" column. */
  why: string;
}

/** A full plan response from Haiku. */
export interface ShellPlan {
  /** One-sentence summary of the operator's intent as understood by the agent. */
  reasoning: string;
  /** Zero or more proposed changes — empty when nothing in the input mapped. */
  changes: ShellPlanChange[];
  /**
   * Fragments of the input the agent couldn't map onto any option. The shell
   * surfaces these in a muted "unsupported intent" row so the user can
   * choose whether to rephrase, fold into house rules, or ignore.
   */
  unsupported: string[];
  /** Rough USD cost delta estimate (positive = more spend). Planner heuristic. */
  roughCostDeltaUsd: number;
  /** Rough wall-clock delta estimate in seconds (positive = slower). */
  roughWallClockDeltaSeconds: number;
  /** Which tool these changes apply to (fully-qualified, e.g. "sast:scan"). */
  toolName: string;
  /** Epoch ms when the plan was produced (for the audit row). */
  producedAt: number;
  /** USD cost the planner itself consumed — shown in the "source" row. */
  planCostUsd: number;
  /** Source tag for the audit trail ("console-agent/r1"). */
  source: string;
}

export interface PlannerInput {
  runtime: AgentRuntime;
  /** Cwd to pass to the runtime. */
  cwd: string;
  /** The module-tool whose options we're planning against. */
  tool: ModuleTool;
  /** Currently stored overrides for this tool (from `shell.moduleOptions`). */
  currentOptions: Record<string, unknown>;
  /** Operator's English text. */
  text: string;
  /** Fully-qualified tool id — used in the output plan for the apply step. */
  toolName: string;
  /** Revision number — r1 for first proposal, r2+ for follow-ups. */
  revision?: number;
  /** Abort controller for cancellation. */
  abortController?: AbortController;
}

// ---------------------------------------------------------------------------
// JSON schema the planner LLM must conform to.
// ---------------------------------------------------------------------------

const PLAN_JSON_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "reasoning",
    "changes",
    "unsupported",
    "rough_cost_delta_usd",
    "rough_wall_clock_delta_seconds",
  ],
  properties: {
    reasoning: { type: "string" },
    changes: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["option", "proposed", "why"],
        properties: {
          option: { type: "string" },
          proposed: {},
          why: { type: "string" },
        },
      },
    },
    unsupported: { type: "array", items: { type: "string" } },
    rough_cost_delta_usd: { type: "number" },
    rough_wall_clock_delta_seconds: { type: "number" },
  },
} as const;

// ---------------------------------------------------------------------------
// Prompt building.
// ---------------------------------------------------------------------------

interface ToolPropertyLite {
  key: string;
  type?: string;
  description?: string;
  default?: unknown;
  enumValues?: unknown[];
  current?: unknown;
}

function extractProperties(tool: ModuleTool, currentOptions: Record<string, unknown>) {
  const schema = tool.inputSchema as Record<string, unknown> | undefined;
  const properties = schema?.["properties"];
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) {
    return [] as ToolPropertyLite[];
  }
  const out: ToolPropertyLite[] = [];
  for (const [key, raw] of Object.entries(properties as Record<string, unknown>)) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const entry = raw as {
      type?: unknown;
      description?: unknown;
      default?: unknown;
      enum?: unknown;
    };
    out.push({
      key,
      type:
        typeof entry.type === "string"
          ? entry.type
          : Array.isArray(entry.type)
            ? (entry.type as unknown[]).map(String).join("|")
            : undefined,
      description: typeof entry.description === "string" ? entry.description : undefined,
      default: entry.default,
      enumValues: Array.isArray(entry.enum) ? entry.enum : undefined,
      current: currentOptions[key],
    });
  }
  return out;
}

function buildSystemPrompt(tool: ModuleTool): string {
  return [
    "You are a planner that turns natural-language operator requests into",
    `precise option changes for the tool "${tool.name}".`,
    "",
    `Tool description: ${tool.description}`,
    "",
    "Rules:",
    "  1. ONLY propose changes to option keys listed under 'Available options'.",
    "  2. Each `proposed` value must match the option's declared type and enum.",
    "  3. If a request fragment cannot be mapped to any option, include it",
    "     verbatim in `unsupported` so the operator sees you heard it.",
    "  4. Be conservative: only include changes the operator actually asked for.",
    "     Don't bump unrelated knobs.",
    "  5. `rough_cost_delta_usd` and `rough_wall_clock_delta_seconds` are",
    "     back-of-envelope estimates — they may be 0 when the change has no",
    "     clear budget impact.",
    "  6. `reasoning` is one short sentence summarising the operator's intent.",
    "",
    "Return valid JSON matching the provided schema.",
  ].join("\n");
}

function buildUserPrompt(input: PlannerInput): string {
  const props = extractProperties(input.tool, input.currentOptions);
  const table = props
    .map((p) => {
      const parts = [
        `- ${p.key}`,
        p.type ? `(${p.type})` : "",
        p.enumValues && p.enumValues.length
          ? `enum=[${p.enumValues.map((v) => JSON.stringify(v)).join(", ")}]`
          : "",
        p.description ? `— ${p.description}` : "",
      ].filter(Boolean);
      const lead = parts.join(" ");
      const cur =
        p.current === undefined
          ? p.default === undefined
            ? "unset"
            : `default=${JSON.stringify(p.default)}`
          : `current=${JSON.stringify(p.current)}`;
      return `  ${lead}  [${cur}]`;
    })
    .join("\n");

  const header = [
    `Operator request (revision ${input.revision ?? 1}):`,
    `  "${input.text}"`,
    "",
    `Available options for ${input.tool.name}:`,
    table || "  (no options declared)",
  ].join("\n");

  return `${header}\n\nReturn a JSON plan.`;
}

// ---------------------------------------------------------------------------
// Planner entry point.
// ---------------------------------------------------------------------------

/**
 * Rough-estimate bounds. The planner can produce silly outputs; we clamp
 * so the UI doesn't display nonsense.
 */
function clamp(n: number, lo: number, hi: number): number {
  if (Number.isNaN(n) || !Number.isFinite(n)) return 0;
  return Math.max(lo, Math.min(hi, n));
}

/**
 * Ask the planner to translate English into an option diff.
 *
 * Throws on any terminal error — shell.ts catches and surfaces as a user-
 * facing error entry in the history.
 */
export async function runPlanner(input: PlannerInput): Promise<ShellPlan> {
  const systemPrompt = buildSystemPrompt(input.tool);
  const userPrompt = buildUserPrompt(input);
  const producedAt = Date.now();

  let structured: unknown;
  let cost = 0;
  let errored: string | undefined;

  for await (const message of input.runtime.query({
    prompt: `${systemPrompt}\n\n${userPrompt}`,
    options: {
      cwd: input.cwd,
      model: "claude-haiku-4-5",
      effort: "low",
      thinkingDisabled: true,
      maxOutputTokens: 1024,
      outputFormat: {
        type: "json_schema",
        schema: PLAN_JSON_SCHEMA as unknown as Record<string, unknown>,
        strict: true,
        retryInvalidStructuredOutput: 1,
      },
      ...(input.abortController ? { abortController: input.abortController } : {}),
    },
  })) {
    if (message.type !== "result") continue;
    if ("structuredOutput" in message || "result" in message) {
      structured = (message as { structuredOutput?: unknown }).structuredOutput;
      cost = (message as { totalCostUsd?: number }).totalCostUsd ?? 0;
    } else if ("errors" in message) {
      const errs = (message as { errors?: string[] }).errors;
      errored = (errs && errs.join("; ")) || (message as { subtype?: string }).subtype;
    }
  }

  if (errored) {
    throw new Error(`Planner failed: ${errored}`);
  }
  if (!structured || typeof structured !== "object") {
    throw new Error("Planner returned no structured output.");
  }

  const raw = structured as {
    reasoning?: string;
    changes?: Array<{ option?: string; proposed?: unknown; why?: string }>;
    unsupported?: string[];
    rough_cost_delta_usd?: number;
    rough_wall_clock_delta_seconds?: number;
  };

  // Drop any proposed change that names an option not in the schema, and
  // stamp each one with the current value so the UI can render a real diff.
  const validKeys = new Set(extractProperties(input.tool, input.currentOptions).map((p) => p.key));
  const changes: ShellPlanChange[] = (raw.changes ?? [])
    .filter((c) => typeof c.option === "string" && validKeys.has(c.option))
    .map((c) => ({
      option: c.option as string,
      current: input.currentOptions[c.option as string] ?? null,
      proposed: c.proposed,
      why: typeof c.why === "string" ? c.why : "",
    }));

  return {
    reasoning: typeof raw.reasoning === "string" ? raw.reasoning : "",
    changes,
    unsupported: Array.isArray(raw.unsupported) ? raw.unsupported.filter(Boolean) : [],
    roughCostDeltaUsd: clamp(Number(raw.rough_cost_delta_usd ?? 0), -5, 50),
    roughWallClockDeltaSeconds: clamp(Number(raw.rough_wall_clock_delta_seconds ?? 0), -600, 3600),
    toolName: input.toolName,
    producedAt,
    planCostUsd: cost,
    source: `console-agent/r${input.revision ?? 1}`,
  };
}

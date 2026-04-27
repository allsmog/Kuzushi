import { normalizeTaskCapabilityIds } from "../capabilities.js";
import { SCAN_PRESETS, type ScanPreset } from "../config/presets.js";
import type { TuneSnapshot } from "../ui/state.js";

export const SAST_SCAN_TOOL_NAME = "sast:scan";

export type SastTaskMode = "auto" | "manual";
export type SastTaskCost = "low" | "med" | "high";
export type SastTaskSource = "preset" | "config" | "auto" | "manual" | "denied" | "dependency";
export type SastTaskState = "[x]" | "[ ]" | "[A]" | "[!]";

export interface SastTaskCapability {
  id: string;
  label: string;
  taskIds: string[];
  cost: SastTaskCost;
  notes: string;
  toggleable?: boolean;
}

export interface SastTaskRow extends SastTaskCapability {
  state: SastTaskState;
  source: SastTaskSource;
  selected: boolean;
  denied: boolean;
}

export interface SastTaskSelectionSummary {
  profile: string;
  mode: SastTaskMode;
  modeLabel: string;
  totalCount: number;
  enabledCount: number;
  blockedCount: number;
  requiredCount: number;
  autoCandidateCount: number;
  activeIndex: number;
  activeRow: SastTaskRow | null;
  activeAction: string;
}

export const SAST_TASK_CAPABILITIES: SastTaskCapability[] = [
  {
    id: "semgrep",
    label: "semgrep",
    taskIds: ["semgrep"],
    cost: "low",
    notes: "pattern scanner",
  },
  {
    id: "codeql",
    label: "codeql",
    taskIds: ["codeql"],
    cost: "high",
    notes: "semantic query scanner",
  },
  {
    id: "agentic-sast",
    label: "agentic-sast",
    taskIds: ["agentic-sast"],
    cost: "high",
    notes: "LLM-driven detector set",
  },
  {
    id: "secrets",
    label: "secrets",
    taskIds: ["secrets-crypto-detect"],
    cost: "low",
    notes: "secrets and crypto misuse",
  },
  {
    id: "security-misconfig",
    label: "security-config",
    taskIds: ["code-config-detect"],
    cost: "low",
    notes: "dangerous APIs and config",
  },
  {
    id: "ssrf",
    label: "ssrf",
    taskIds: ["ssrf-detect"],
    cost: "med",
    notes: "web request dataflow",
  },
  {
    id: "command-injection",
    label: "command-injection",
    taskIds: ["command-injection-detect"],
    cost: "med",
    notes: "shell/process execution",
  },
  {
    id: "template-injection",
    label: "template-injection",
    taskIds: ["template-injection-detect"],
    cost: "med",
    notes: "template sinks",
  },
  {
    id: "deserialization",
    label: "deserialization",
    taskIds: ["deserialization-detect"],
    cost: "med",
    notes: "unsafe object loading",
  },
  {
    id: "xxe",
    label: "xxe",
    taskIds: ["xxe-detect"],
    cost: "med",
    notes: "XML parser hardening",
  },
  {
    id: "prototype-pollution",
    label: "prototype-pollution",
    taskIds: ["prototype-pollution-detect"],
    cost: "med",
    notes: "JS object merge risk",
  },
  {
    id: "graphql-security",
    label: "graphql-security",
    taskIds: ["graphql-security-detect"],
    cost: "med",
    notes: "GraphQL resolver risk",
  },
  {
    id: "auth-logic",
    label: "auth-logic",
    taskIds: ["auth-logic-detect"],
    cost: "high",
    notes: "authorization workflows",
  },
  {
    id: "race-condition",
    label: "race-condition",
    taskIds: ["race-condition-detect"],
    cost: "med",
    notes: "TOCTOU and concurrency",
  },
  {
    id: "supply-chain",
    label: "supply-chain",
    taskIds: ["supply-chain-detect"],
    cost: "med",
    notes: "dependency and build risk",
  },
  {
    id: "taint-analysis",
    label: "taint-analysis",
    taskIds: ["taint-cwe-select", "taint-iris"],
    cost: "high",
    notes: "source to sink tracing",
  },
  {
    id: "threat-hunt",
    label: "threat-hunt",
    taskIds: ["threat-hunt"],
    cost: "high",
    notes: "actor-driven hunting",
  },
  {
    id: "systems-hunt",
    label: "systems-hunt",
    taskIds: [
      "systems-context-gatherer",
      "systems-invariant-extract",
      "systems-trigger-synth",
      "systems-hunt",
    ],
    cost: "high",
    notes: "systems/code invariant hunt",
  },
  {
    id: "context-gathering",
    label: "context",
    taskIds: ["context-gatherer", "context-enricher"],
    cost: "low",
    notes: "required infrastructure",
    toggleable: false,
  },
];

export function readSastTaskMode(options: Record<string, unknown> | undefined): SastTaskMode {
  return options?.["taskMode"] === "manual" ? "manual" : "auto";
}

export function readStringArrayOption(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string" && item.trim() !== "");
  }
  if (typeof value === "string") {
    return value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return [];
}

export function readDisabledSastTasks(options: Record<string, unknown> | undefined): string[] {
  return readStringArrayOption(options?.["disabledTasks"]);
}

export function readManualSastTasks(options: Record<string, unknown> | undefined): string[] {
  return readStringArrayOption(options?.["tasks"]);
}

export function normalizeSastTaskIds(ids: readonly string[]): string[] {
  return normalizeTaskCapabilityIds(
    ids.map((id) => (id.trim() === "agentic" ? "agentic-sast" : id)),
  );
}

export function resolveSastTaskAtCursor(cursor: number | undefined): SastTaskCapability {
  const clamped = Math.max(0, Math.min(SAST_TASK_CAPABILITIES.length - 1, cursor ?? 0));
  return SAST_TASK_CAPABILITIES[clamped] ?? SAST_TASK_CAPABILITIES[0]!;
}

export function resolveSastTaskCapability(id: string): SastTaskCapability | undefined {
  const normalized = id.trim();
  if (!normalized) return undefined;
  return SAST_TASK_CAPABILITIES.find(
    (capability) =>
      capability.id === normalized ||
      capability.label === normalized ||
      capability.taskIds.includes(normalized),
  );
}

export function updateDisabledSastTask(
  options: Record<string, unknown>,
  id: string,
  blocked: boolean,
): Record<string, unknown> {
  const disabled = new Set(readDisabledSastTasks(options));
  if (blocked) disabled.add(id);
  else disabled.delete(id);
  return writeDisabledTasks(options, [...disabled]);
}

export function toggleDisabledSastTask(
  options: Record<string, unknown>,
  id: string,
): Record<string, unknown> {
  const disabled = new Set(readDisabledSastTasks(options));
  return updateDisabledSastTask(options, id, !disabled.has(id));
}

export function resetSastTaskOptions(options: Record<string, unknown>): Record<string, unknown> {
  const next = { ...options };
  delete next["taskMode"];
  delete next["disabledTasks"];
  delete next["tasks"];
  return next;
}

export function setSastTaskMode(
  options: Record<string, unknown>,
  mode: SastTaskMode,
  fallbackTasks: readonly string[],
): Record<string, unknown> {
  const next: Record<string, unknown> = { ...options, taskMode: mode };
  if (mode === "manual" && readManualSastTasks(next).length === 0) {
    next["tasks"] = [...fallbackTasks];
  }
  return next;
}

export function defaultManualSastTasks(
  options: Record<string, unknown> | undefined,
  tune: TuneSnapshot | undefined,
): string[] {
  const explicit = readManualSastTasks(options);
  if (explicit.length > 0) return explicit;

  const preset = typeof options?.["preset"] === "string" ? options["preset"] : tune?.preset;
  const presetTasks = isScanPreset(preset) ? SCAN_PRESETS[preset].tasks : undefined;
  if (presetTasks && presetTasks.length > 0) return [...presetTasks];
  return [...(tune?.tasks ?? [])];
}

export function buildSastTaskRows(input: {
  options?: Record<string, unknown>;
  tune?: TuneSnapshot;
}): SastTaskRow[] {
  const { options, tune } = input;
  const mode = readSastTaskMode(options);
  const disabledSet = new Set(normalizeSastTaskIds(readDisabledSastTasks(options)));
  const manualSet = new Set(normalizeSastTaskIds(readManualSastTasks(options)));
  const preset = typeof options?.["preset"] === "string" ? options["preset"] : tune?.preset;
  const presetTasks = isScanPreset(preset) ? SCAN_PRESETS[preset].tasks : undefined;
  const configured = new Set(normalizeSastTaskIds(presetTasks ?? tune?.tasks ?? []));

  return SAST_TASK_CAPABILITIES.map((capability) => {
    const taskHit = capability.taskIds.some((taskId) => disabledSet.has(taskId));
    const denied = taskHit || disabledSet.has(capability.id);
    if (denied) {
      return { ...capability, state: "[ ]", source: "denied", selected: false, denied };
    }

    if (capability.toggleable === false) {
      return {
        ...capability,
        state: "[!]",
        source: "dependency",
        selected: true,
        denied: false,
      };
    }

    if (mode === "manual") {
      const selected = capability.taskIds.some((taskId) => manualSet.has(taskId));
      return {
        ...capability,
        state: selected ? "[x]" : "[ ]",
        source: "manual",
        selected,
        denied: false,
      };
    }

    const selectedByConfig = capability.taskIds.some((taskId) => configured.has(taskId));
    return {
      ...capability,
      state: selectedByConfig ? "[x]" : "[A]",
      source: selectedByConfig ? (presetTasks ? "preset" : "config") : "auto",
      selected: selectedByConfig,
      denied: false,
    };
  });
}

export function buildSastTaskSelectionSummary(input: {
  options?: Record<string, unknown>;
  tune?: TuneSnapshot;
  cursor?: number;
  rows?: SastTaskRow[];
}): SastTaskSelectionSummary {
  const rows = input.rows ?? buildSastTaskRows(input);
  const mode = readSastTaskMode(input.options);
  const profile =
    typeof input.options?.["preset"] === "string"
      ? input.options["preset"]
      : (input.tune?.preset ?? "standard");
  const activeIndex =
    rows.length > 0 ? Math.max(0, Math.min(rows.length - 1, input.cursor ?? 0)) : 0;
  const activeRow = rows[activeIndex] ?? null;
  return {
    profile,
    mode,
    modeLabel: mode === "auto" ? "auto + denylist" : "manual allowlist",
    totalCount: rows.length,
    enabledCount: rows.filter((row) => row.selected).length,
    blockedCount: rows.filter((row) => row.denied).length,
    requiredCount: rows.filter((row) => row.toggleable === false).length,
    autoCandidateCount: rows.filter((row) => row.state === "[A]").length,
    activeIndex,
    activeRow,
    activeAction: formatSastTaskActiveAction(activeRow),
  };
}

export function formatSastTaskStateLine(summary: SastTaskSelectionSummary): string {
  const parts = [
    `profile ${summary.profile}`,
    summary.modeLabel,
    `${summary.enabledCount}/${summary.totalCount} enabled`,
    `${summary.blockedCount} blocked`,
  ];
  if (summary.requiredCount > 0) parts.push(`${summary.requiredCount} required`);
  if (summary.autoCandidateCount > 0) parts.push(`${summary.autoCandidateCount} auto`);
  return parts.join(" · ");
}

export function formatSastTaskLegend(): string {
  return "[x] enabled  [A] auto candidate  [ ] blocked/off  [!] required";
}

export function formatSastTaskFeedback(
  headline: string,
  options: Record<string, unknown> | undefined,
  tune: TuneSnapshot | undefined,
): string {
  const summary = buildSastTaskSelectionSummary({ options, tune });
  return `${headline}\n${formatSastTaskStateLine(summary)}`;
}

function writeDisabledTasks(
  options: Record<string, unknown>,
  disabledTasks: string[],
): Record<string, unknown> {
  const next = { ...options };
  if (disabledTasks.length === 0) delete next["disabledTasks"];
  else next["disabledTasks"] = disabledTasks;
  return next;
}

function formatSastTaskActiveAction(row: SastTaskRow | null): string {
  if (!row) return "No task selected.";
  if (row.toggleable === false) return `${row.label} is required infrastructure.`;
  if (row.denied) return `Space allows ${row.label}.`;
  return `Space blocks ${row.label}.`;
}

function isScanPreset(value: unknown): value is ScanPreset {
  return (
    value === "safe" ||
    value === "fast" ||
    value === "standard" ||
    value === "deep" ||
    value === "reference"
  );
}

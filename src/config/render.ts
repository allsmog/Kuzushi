/**
 * Human-readable renderer for Kuzushi config.
 *
 * Drives both the CLI `kuzushi config get` (no key) output and the shell's
 * `/config` slash command. Suppresses keys that still match `DEFAULTS` so the
 * summary highlights the user's actual overrides — the raw merged config has
 * ~50 top-level keys and a deeply-nested `taskConfig`, most of which most
 * users never touch.
 *
 * Pure functions, no I/O, no Ink — safe to call from CLI, shell, or tests.
 */

import type { KuzushiConfig } from "../types.js";
import { DEFAULTS } from "./defaults.js";

export interface ConfigRow {
  /** Dotted key path, e.g. "verifyMaxTurns" or "taskConfig.semgrep.configFlag". */
  key: string;
  /** Pretty-formatted current value (string). */
  value: string;
  /** Pretty-formatted default value, or undefined if the key has no default. */
  defaultValue: string | undefined;
  isDefault: boolean;
}

export interface ConfigGroup {
  title: string;
  /** Overrides (keys whose value differs from DEFAULTS). Always shown. */
  overrides: ConfigRow[];
  /** Default rows (hidden unless showDefaults is set). */
  defaults: ConfigRow[];
}

export interface RenderedConfig {
  groups: ConfigGroup[];
  /** Task entries whose contents exactly match DEFAULTS.taskConfig[name]. */
  noopTaskOverrides: string[];
  /**
   * Custom task entries (not in DEFAULTS.taskConfig) whose content is a
   * byte-for-byte copy of another task's DEFAULTS block. Map from the copy's
   * task id to the template task id it mirrors.
   */
  templateCopies: Array<{ taskId: string; copiedFrom: string }>;
  /** Task entries not present in DEFAULTS.taskConfig (user-added tasks). */
  customTaskIds: string[];
  totalHiddenDefaults: number;
}

/** Matchers run in order; first hit wins. "other" is the catch-all. */
const GROUP_RULES: Array<{ title: string; match: (key: string) => boolean }> = [
  {
    title: "Model & runtime",
    match: (k) =>
      k === "model" ||
      k === "agentRuntimeBackend" ||
      k === "agentRuntimeConfig" ||
      k === "busBackend" ||
      k === "streamingEnabled" ||
      k === "streamingPort" ||
      k === "ensembleModels",
  },
  {
    title: "Scan pipeline",
    match: (k) =>
      k === "tasks" ||
      k === "severity" ||
      k === "excludePatterns" ||
      k === "scanMode" ||
      k === "enableDynamicTaskSelection" ||
      k === "externalTasks" ||
      k === "enableExternalTasks" ||
      k.startsWith("incrementalCache") ||
      k === "incrementalDepTracking" ||
      k === "diffBase" ||
      k === "taintDiffBase" ||
      k === "taintDiffMode" ||
      k === "monorepo",
  },
  {
    title: "Triage",
    match: (k) =>
      k.startsWith("triage") ||
      k === "maxTriageRetries" ||
      k === "prioritizeFindings" ||
      k === "llmRescoreEnabled" ||
      k === "llmRescoreThreshold" ||
      k.startsWith("fpFilter") ||
      k === "designDecisionClassifier" ||
      k === "skipTriageForHighConfidenceAgentic" ||
      k === "confidenceCalibration" ||
      k === "confidenceSignalWeights",
  },
  {
    title: "Verify",
    match: (k) => k.startsWith("verify") || k === "maxVerifyRetries",
  },
  {
    title: "PoC & patching",
    match: (k) =>
      k.startsWith("poc") ||
      k.startsWith("patch") ||
      k.startsWith("autoPatch") ||
      k === "maxPocHarnessRetries" ||
      k === "patchingEnabled",
  },
  {
    title: "Analysis depth",
    match: (k) =>
      k.startsWith("variant") ||
      k === "astIndexEnabled" ||
      k === "callGraphAssistEnabled" ||
      k === "codeGraphEnabled" ||
      k.startsWith("multiStrategy") ||
      k === "autoRuleGeneration" ||
      k.startsWith("dynamic") ||
      k.startsWith("crypto") ||
      k === "coverageGuidedEnabled" ||
      k === "enableContextGathering" ||
      k === "enableContextEnrichment" ||
      k === "taintGroundingEnabled" ||
      k === "trajectoryMemory" ||
      k === "trajectoryMaxExemplars",
  },
  {
    title: "Output & logging",
    match: (k) =>
      k === "reportOutput" ||
      k === "sarifOutput" ||
      k === "jsonOutput" ||
      k === "csvOutput" ||
      k === "jsonlOutput" ||
      k === "auditLog" ||
      k === "retryBackoffMs" ||
      k === "retryBackoffMultiplier",
  },
];

/** Group key for the task-overrides bucket (rendered separately). */
const TASK_GROUP_TITLE = "Task overrides";
/** Group key for the catch-all. */
const OTHER_GROUP_TITLE = "Other";

/**
 * Compute a structured diff of the config against `DEFAULTS`, bucketed into
 * groups, with `taskConfig` entries collapsed when they match defaults.
 */
export function renderConfig(config: KuzushiConfig): RenderedConfig {
  const groups = new Map<string, ConfigGroup>();
  const ensureGroup = (title: string): ConfigGroup => {
    let group = groups.get(title);
    if (!group) {
      group = { title, overrides: [], defaults: [] };
      groups.set(title, group);
    }
    return group;
  };

  // Seed groups in the declared order so output is stable.
  for (const rule of GROUP_RULES) ensureGroup(rule.title);

  const noopTaskOverrides: string[] = [];
  const templateCopies: Array<{ taskId: string; copiedFrom: string }> = [];
  const customTaskIds: string[] = [];
  let totalHiddenDefaults = 0;

  for (const [key, value] of topLevelEntries(config)) {
    if (key === "taskConfig") continue; // handled separately below

    const defaultValue = DEFAULT_RECORD[key];
    const isDefault = deepEqual(value, defaultValue);
    const row: ConfigRow = {
      key,
      value: formatDisplayValue(key, value),
      defaultValue: defaultValue === undefined ? undefined : formatDisplayValue(key, defaultValue),
      isDefault,
    };

    const group = ensureGroup(pickGroupTitle(key));
    if (isDefault) {
      group.defaults.push(row);
      totalHiddenDefaults++;
    } else {
      group.overrides.push(row);
    }
  }

  // taskConfig: collapse entries that exactly match DEFAULTS.taskConfig[name].
  const taskGroup = ensureGroup(TASK_GROUP_TITLE);
  const defaultTaskConfig = (DEFAULTS.taskConfig ?? {}) as Record<string, unknown>;
  const userTaskConfig = (config.taskConfig ?? {}) as Record<string, unknown>;
  for (const taskId of Object.keys(userTaskConfig).sort()) {
    const userValue = userTaskConfig[taskId];
    const defaultValue = defaultTaskConfig[taskId];
    const inDefaults = taskId in defaultTaskConfig;

    if (inDefaults && deepEqual(userValue, defaultValue)) {
      noopTaskOverrides.push(taskId);
      totalHiddenDefaults++;
      continue;
    }

    if (!inDefaults) {
      customTaskIds.push(taskId);
      // Detect the common "pasted template" anti-pattern: content identical
      // to another task's DEFAULTS block.
      const matchedTemplate = findTemplateTaskMatch(userValue, defaultTaskConfig);
      if (matchedTemplate) {
        templateCopies.push({ taskId, copiedFrom: matchedTemplate });
        // Count this whole block as a hidden default for the footer.
        if (isPlainObject(userValue)) {
          totalHiddenDefaults += Object.keys(userValue).length;
        }
        continue;
      }
    }

    // Render each sub-key on its own line (e.g. "taskConfig.semgrep.configFlag").
    if (isPlainObject(userValue)) {
      const defaultObj = isPlainObject(defaultValue) ? defaultValue : {};
      for (const subKey of Object.keys(userValue).sort()) {
        const subValue = (userValue as Record<string, unknown>)[subKey];
        const subDefault = (defaultObj as Record<string, unknown>)[subKey];
        const subIsDefault = deepEqual(subValue, subDefault);
        const rowKey = `taskConfig.${taskId}.${subKey}`;
        const row: ConfigRow = {
          key: rowKey,
          value: formatDisplayValue(rowKey, subValue),
          defaultValue:
            subDefault === undefined ? undefined : formatDisplayValue(rowKey, subDefault),
          isDefault: subIsDefault,
        };
        if (subIsDefault) {
          taskGroup.defaults.push(row);
          totalHiddenDefaults++;
        } else {
          taskGroup.overrides.push(row);
        }
      }
    }
  }

  return {
    groups: [...groups.values()],
    noopTaskOverrides,
    templateCopies,
    customTaskIds,
    totalHiddenDefaults,
  };
}

function findTemplateTaskMatch(
  value: unknown,
  defaultTaskConfig: Record<string, unknown>,
): string | undefined {
  if (!isPlainObject(value) || Object.keys(value).length === 0) return undefined;
  for (const [templateId, templateValue] of Object.entries(defaultTaskConfig)) {
    if (!isPlainObject(templateValue)) continue;
    if (Object.keys(templateValue).length === 0) continue;
    if (deepEqual(value, templateValue)) return templateId;
  }
  return undefined;
}

export interface FormatOptions {
  /** Include default-valued rows in output. */
  showDefaults?: boolean;
  /** Path to the config file (for footer). */
  configPath?: string;
  /** Max total width (for value truncation). Defaults to 100. */
  maxWidth?: number;
}

/**
 * Render a config as human-readable text. Suitable for both CLI stdout and
 * the shell's slash-command output string.
 */
export function formatConfigText(config: KuzushiConfig, opts: FormatOptions = {}): string {
  const { showDefaults = false, configPath, maxWidth = 100 } = opts;
  const rendered = renderConfig(config);

  const lines: string[] = [];
  lines.push("Kuzushi config" + (showDefaults ? " (all keys)" : " (overrides only)"));
  if (configPath) lines.push(`  source: ${configPath}`);
  lines.push("");

  let totalVisible = 0;
  for (const group of rendered.groups) {
    const visibleRows = showDefaults ? [...group.overrides, ...group.defaults] : group.overrides;
    if (visibleRows.length === 0) continue;

    totalVisible += visibleRows.length;
    lines.push(group.title);
    const labelWidth = Math.min(40, Math.max(...visibleRows.map((r) => r.key.length)));
    for (const row of visibleRows) {
      lines.push(formatRow(row, labelWidth, maxWidth));
    }
    lines.push("");
  }

  // Collapsed task entries: one line summary
  if (!showDefaults && rendered.noopTaskOverrides.length > 0) {
    lines.push(`${TASK_GROUP_TITLE} — defaults (no-op overrides in your config)`);
    lines.push(
      `  ${rendered.noopTaskOverrides.length} task${rendered.noopTaskOverrides.length === 1 ? "" : "s"}: ${rendered.noopTaskOverrides.join(", ")}`,
    );
    lines.push(
      "  These match DEFAULTS; remove them with `/config unset taskConfig.<id>` to declutter your config.json.",
    );
    lines.push("");
  }

  // Custom tasks that are byte-copies of an existing DEFAULTS template
  if (!showDefaults && rendered.templateCopies.length > 0) {
    lines.push(`${TASK_GROUP_TITLE} — template copies (content matches an existing default)`);
    const byTemplate = new Map<string, string[]>();
    for (const copy of rendered.templateCopies) {
      const list = byTemplate.get(copy.copiedFrom) ?? [];
      list.push(copy.taskId);
      byTemplate.set(copy.copiedFrom, list);
    }
    for (const [template, copies] of byTemplate) {
      lines.push(
        `  ${copies.length} task${copies.length === 1 ? "" : "s"} copied from ${template} defaults: ${copies.join(", ")}`,
      );
    }
    lines.push("  Consider deleting these blocks — they'd inherit the same values automatically.");
    lines.push("");
  }

  if (totalVisible === 0) {
    lines.push("  (all keys at defaults)");
    lines.push("");
  }

  if (!showDefaults && rendered.totalHiddenDefaults > 0) {
    lines.push(
      `${rendered.totalHiddenDefaults} default value${rendered.totalHiddenDefaults === 1 ? "" : "s"} hidden. Use --all (CLI) or /config --all (shell) to see everything.`,
    );
  }

  return lines.join("\n");
}

// ── internal helpers ────────────────────────────────────────────────────────

function pickGroupTitle(key: string): string {
  for (const rule of GROUP_RULES) {
    if (rule.match(key)) return rule.title;
  }
  return OTHER_GROUP_TITLE;
}

function topLevelEntries(config: KuzushiConfig): Array<[string, unknown]> {
  const record = config as unknown as Record<string, unknown>;
  return Object.keys(record)
    .sort()
    .map((k) => [k, record[k]] as [string, unknown]);
}

const DEFAULT_RECORD = DEFAULTS as unknown as Record<string, unknown>;

function formatRow(row: ConfigRow, labelWidth: number, maxWidth: number): string {
  const label = row.key.padEnd(labelWidth);
  const marker = row.isDefault ? "  " : "• ";
  const suffix =
    row.isDefault || row.defaultValue === undefined || row.defaultValue === row.value
      ? ""
      : `   (default: ${truncate(row.defaultValue, 30)})`;
  const valueBudget = Math.max(10, maxWidth - labelWidth - marker.length - suffix.length - 4);
  return `  ${marker}${label}  ${truncate(row.value, valueBudget)}${suffix}`;
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, Math.max(0, max - 1))}…`;
}

const SECRET_KEY_PATTERN = /(api[_-]?key|token|secret|password|credential|oauth)/i;

function formatDisplayValue(keyPath: string, value: unknown): string {
  if (SECRET_KEY_PATTERN.test(keyPath) && typeof value === "string" && value.length > 0) {
    return "***redacted***";
  }
  if (value === undefined) return "(unset)";
  if (value === null) return "null";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    return `[${value.map((v, i) => formatDisplayValue(`${keyPath}.${i}`, v)).join(", ")}]`;
  }
  if (typeof value === "object") {
    try {
      return JSON.stringify(redactNestedSecrets(value, keyPath));
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function redactNestedSecrets(value: unknown, keyPath = ""): unknown {
  if (Array.isArray(value)) {
    return value.map((item, index) => redactNestedSecrets(item, `${keyPath}.${index}`));
  }
  if (!isPlainObject(value)) return value;
  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    const childPath = keyPath ? `${keyPath}.${key}` : key;
    out[key] =
      SECRET_KEY_PATTERN.test(childPath) && typeof child === "string" && child.length > 0
        ? "***redacted***"
        : redactNestedSecrets(child, childPath);
  }
  return out;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === undefined || b === undefined) return false;
  if (a === null || b === null) return a === b;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return false;
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  if (typeof a === "object" && typeof b === "object") {
    const aKeys = Object.keys(a as Record<string, unknown>).sort();
    const bKeys = Object.keys(b as Record<string, unknown>).sort();
    if (aKeys.length !== bKeys.length) return false;
    for (let i = 0; i < aKeys.length; i++) {
      if (aKeys[i] !== bKeys[i]) return false;
    }
    for (const k of aKeys) {
      if (!deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k])) {
        return false;
      }
    }
    return true;
  }
  return false;
}

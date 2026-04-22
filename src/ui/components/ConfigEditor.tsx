/**
 * ConfigEditor — interactive TUI editor for KuzushiConfig.
 *
 * Layout:
 *   ╭─ Configuration ─────────────────────────────────────────────╮
 *     > ▸ Runtime & Model            5 fields
 *       ▸ Scan Pipeline             11 fields
 *       ▸ Triage                    13 fields
 *       …
 *
 * Navigation: arrows / j-k. Space toggles a section open or a boolean
 * inline. Enter drills into the value editor for the focused field
 * (or expands a section header). 's' saves the diff; Esc cancels.
 *
 * Sections are collapsed by default to keep the panel short; the user
 * opts into the density they want. Task config is its own section
 * where each task id is a drill-down.
 */
import { Box, Text, useInput } from "ink";
import type React from "react";
import { useMemo, useState } from "react";
import type { ConfigPatchEntry } from "../../config.js";
import type { KuzushiConfig } from "../../types.js";
import { boxFooter, boxHeader, terminalCardWidth } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { SPACING, tokens } from "../tokens.js";
import {
  FIELDS,
  type FieldDescriptor,
  type FieldType,
  fieldsInSection,
  inferFieldType,
  isKnownTopLevelField,
  SECTIONS,
  type SectionId,
} from "./ConfigEditor.fields.js";
import {
  BoolEditor,
  EnumEditor,
  NumberEditor,
  StringEditor,
  StringListEditor,
} from "./ConfigEditor.valueEditors.js";

const SECRET_KEY_PATTERN = /(apiKey|token|secret|password)/i;

export interface ConfigEditorProps {
  initialConfig: KuzushiConfig;
  configPath: string;
  focusKey?: string;
  onComplete: (patch: ConfigPatchEntry[]) => void;
  onCancel: () => void;
}

type Row =
  | { kind: "section"; section: SectionId; title: string; childCount: number; expanded: boolean }
  | { kind: "field"; descriptor: FieldDescriptor; value: unknown }
  | { kind: "task"; taskId: string; childCount: number }
  | { kind: "other"; topKey: string; value: unknown };

type DrillTarget = { kind: "task"; taskId: string };

type DrillRow = { kind: "back" } | { kind: "field"; descriptor: FieldDescriptor; value: unknown };

function getValueAtPath(root: unknown, dottedPath: string): unknown {
  let cursor: unknown = root;
  for (const part of dottedPath.split(".")) {
    if (cursor == null || typeof cursor !== "object") return undefined;
    cursor = (cursor as Record<string, unknown>)[part];
  }
  return cursor;
}

function setValueAtPath(
  root: Record<string, unknown>,
  dottedPath: string,
  value: unknown,
): Record<string, unknown> {
  const parts = dottedPath.split(".");
  const next = { ...root };
  let cursor: Record<string, unknown> = next;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i]!;
    const existing = cursor[part];
    const cloned: Record<string, unknown> =
      existing && typeof existing === "object" && !Array.isArray(existing)
        ? { ...(existing as Record<string, unknown>) }
        : {};
    cursor[part] = cloned;
    cursor = cloned;
  }
  if (value === undefined) {
    delete cursor[parts[parts.length - 1]!];
  } else {
    cursor[parts[parts.length - 1]!] = value;
  }
  return next;
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  if (typeof a === "object" && typeof b === "object") {
    const ak = Object.keys(a as object).sort();
    const bk = Object.keys(b as object).sort();
    if (ak.length !== bk.length) return false;
    if (!ak.every((k, i) => k === bk[i])) return false;
    return ak.every((k) =>
      deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
    );
  }
  return false;
}

function formatValue(value: unknown, label: string): string {
  if (value === undefined || value === null) return tokens.muted("(unset)");
  if (SECRET_KEY_PATTERN.test(label) && typeof value === "string" && value.length > 0) {
    return tokens.muted(`*** (len=${value.length})`);
  }
  if (typeof value === "boolean") return value ? tokens.success("true") : tokens.danger("false");
  if (typeof value === "number") return tokens.value(String(value));
  if (typeof value === "string") {
    if (value.length === 0) return tokens.muted('""');
    return tokens.value(value.length > 60 ? `${value.slice(0, 57)}…` : value);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return tokens.muted("[]");
    const preview = value.slice(0, 4).map(String).join(", ");
    const more = value.length > 4 ? `, +${value.length - 4} more` : "";
    return tokens.value(`[${preview}${more}]`);
  }
  if (typeof value === "object") {
    const keys = Object.keys(value as object);
    return tokens.muted(`{${keys.length} key${keys.length === 1 ? "" : "s"}}`);
  }
  return tokens.value(String(value));
}

function defaultExpandedSection(focusKey: string | undefined): SectionId | null {
  if (!focusKey) return null;
  const desc = FIELDS.find((f) => f.path === focusKey);
  if (desc) return desc.section;
  if (focusKey === "taskConfig" || focusKey.startsWith("taskConfig.")) return "tasks";
  return "other";
}

export function ConfigEditor({
  initialConfig,
  configPath: cfgPath,
  focusKey,
  onComplete,
  onCancel,
}: ConfigEditorProps): React.ReactElement {
  const [cfg, setCfg] = useState<KuzushiConfig>(initialConfig);
  const [expanded, setExpanded] = useState<Set<SectionId>>(() => {
    const initial = new Set<SectionId>();
    const auto = defaultExpandedSection(focusKey);
    if (auto) initial.add(auto);
    return initial;
  });
  const [drill, setDrill] = useState<DrillTarget | null>(null);
  const [editingPath, setEditingPath] = useState<string | null>(focusKey ?? null);
  const [cursor, setCursor] = useState<number>(0);

  // ── Compute visible rows ─────────────────────────────────────────────
  const otherKeys = useMemo<string[]>(() => {
    const keys = Object.keys(cfg as unknown as Record<string, unknown>);
    return keys.filter((k) => !isKnownTopLevelField(k)).sort();
  }, [cfg]);

  const taskIds = useMemo<string[]>(() => {
    return Object.keys(cfg.taskConfig ?? {}).sort();
  }, [cfg.taskConfig]);

  const rows = useMemo<Row[]>(() => {
    if (drill) return [];
    const out: Row[] = [];
    for (const section of SECTIONS) {
      if (section.id === "other" && otherKeys.length === 0) continue;
      const isExpanded = expanded.has(section.id);
      let childCount = 0;
      if (section.id === "tasks") childCount = taskIds.length;
      else if (section.id === "other") childCount = otherKeys.length;
      else childCount = fieldsInSection(section.id).length;
      out.push({
        kind: "section",
        section: section.id,
        title: section.title,
        childCount,
        expanded: isExpanded,
      });
      if (!isExpanded) continue;
      if (section.id === "tasks") {
        for (const taskId of taskIds) {
          const sub = (cfg.taskConfig ?? {})[taskId];
          const keys = sub && typeof sub === "object" ? Object.keys(sub as object) : [];
          out.push({ kind: "task", taskId, childCount: keys.length });
        }
      } else if (section.id === "other") {
        for (const k of otherKeys) {
          out.push({
            kind: "other",
            topKey: k,
            value: (cfg as unknown as Record<string, unknown>)[k],
          });
        }
      } else {
        for (const desc of fieldsInSection(section.id)) {
          out.push({ kind: "field", descriptor: desc, value: getValueAtPath(cfg, desc.path) });
        }
      }
    }
    return out;
  }, [cfg, expanded, taskIds, otherKeys, drill]);

  const drillRows = useMemo<DrillRow[]>(() => {
    if (!drill) return [];
    const sub = (cfg.taskConfig ?? {})[drill.taskId];
    if (!sub || typeof sub !== "object") return [{ kind: "back" }];
    const subRecord = sub as Record<string, unknown>;
    const out: DrillRow[] = [{ kind: "back" }];
    for (const k of Object.keys(subRecord).sort()) {
      const v = subRecord[k];
      const inferred = inferFieldType(v);
      out.push({
        kind: "field",
        value: v,
        descriptor: {
          path: `taskConfig.${drill.taskId}.${k}`,
          label: k,
          description: `taskConfig.${drill.taskId}.${k}`,
          section: "tasks",
          type: inferred,
        },
      });
    }
    return out;
  }, [cfg.taskConfig, drill]);

  const visibleSize = drill ? drillRows.length : rows.length;
  const safeCursor = Math.min(cursor, Math.max(0, visibleSize - 1));

  const editingDescriptor = useMemo<FieldDescriptor | null>(() => {
    if (!editingPath) return null;
    const inMain = rows.find(
      (r): r is Extract<Row, { kind: "field" } | { kind: "other" }> =>
        (r.kind === "field" && r.descriptor.path === editingPath) ||
        (r.kind === "other" && r.topKey === editingPath),
    );
    if (inMain) {
      if (inMain.kind === "field") return inMain.descriptor;
      const inferred = inferFieldType(inMain.value);
      return {
        path: inMain.topKey,
        label: inMain.topKey,
        description: `Unknown field (${typeof inMain.value}).`,
        section: "other",
        type: inferred,
      };
    }
    if (drill) {
      const drillRow = drillRows.find(
        (r): r is Extract<DrillRow, { kind: "field" }> =>
          r.kind === "field" && r.descriptor.path === editingPath,
      );
      if (drillRow) return drillRow.descriptor;
    }
    return null;
  }, [editingPath, rows, drillRows, drill]);

  const editingValue = editingDescriptor ? getValueAtPath(cfg, editingDescriptor.path) : undefined;

  // ── Keybindings ─────────────────────────────────────────────────────
  useRegisterKeybindings(
    editingPath
      ? []
      : drill
        ? [
            { keys: "↑/↓", label: "Navigate" },
            { keys: "Enter", label: "Edit / Back" },
            { keys: "Esc", label: "Back" },
            { keys: "s", label: "Save", secondary: true },
          ]
        : [
            { keys: "↑/↓", label: "Navigate" },
            { keys: "Space", label: "Expand / Toggle" },
            { keys: "Enter", label: "Edit" },
            { keys: "s", label: "Save" },
            { keys: "Esc", label: "Cancel" },
          ],
  );

  // ── Input handler ────────────────────────────────────────────────────
  useInput(
    (input, key) => {
      if (editingPath) return; // value editor owns input
      const size = visibleSize;
      if (key.upArrow || input === "k") {
        if (size === 0) return;
        setCursor((c) => (c - 1 + size) % size);
        return;
      }
      if (key.downArrow || input === "j") {
        if (size === 0) return;
        setCursor((c) => (c + 1) % size);
        return;
      }
      if (input === "s") {
        commitSave();
        return;
      }
      if (key.escape) {
        if (drill) {
          setDrill(null);
          setCursor(0);
          return;
        }
        onCancel();
        return;
      }
      if (drill) {
        const row = drillRows[safeCursor];
        if (!row) return;
        if (row.kind === "back" && key.return) {
          setDrill(null);
          setCursor(0);
          return;
        }
        if (row.kind === "field" && key.return) {
          setEditingPath(row.descriptor.path);
          return;
        }
        return;
      }
      const row = rows[safeCursor];
      if (!row) return;
      if (row.kind === "section") {
        if (input === " " || key.return) {
          setExpanded((prev) => {
            const next = new Set(prev);
            if (next.has(row.section)) next.delete(row.section);
            else next.add(row.section);
            return next;
          });
        }
        return;
      }
      if (row.kind === "task") {
        if (key.return || input === " ") {
          setDrill({ kind: "task", taskId: row.taskId });
          setCursor(0);
        }
        return;
      }
      if (row.kind === "field") {
        if (input === " " && row.descriptor.type.kind === "bool") {
          // Inline boolean toggle without entering edit mode.
          const cur = getValueAtPath(cfg, row.descriptor.path);
          setCfg(
            (prev) =>
              setValueAtPath(
                prev as unknown as Record<string, unknown>,
                row.descriptor.path,
                !(cur === true),
              ) as unknown as KuzushiConfig,
          );
          return;
        }
        if (key.return) {
          setEditingPath(row.descriptor.path);
        }
        return;
      }
      if (row.kind === "other") {
        if (key.return) setEditingPath(row.topKey);
      }
    },
    { isActive: !editingPath },
  );

  // ── Save: compute diff against initialConfig as dotted-path entries ───
  function commitSave(): void {
    const entries: ConfigPatchEntry[] = [];
    // Top-level keys (excluding taskConfig — handled separately)
    const initRec = initialConfig as unknown as Record<string, unknown>;
    const curRec = cfg as unknown as Record<string, unknown>;
    const allTopKeys = new Set<string>([...Object.keys(initRec), ...Object.keys(curRec)]);
    for (const k of allTopKeys) {
      if (k === "taskConfig") continue;
      const before = initRec[k];
      const after = curRec[k];
      if (!deepEqual(before, after)) {
        entries.push({ path: k, value: after });
      }
    }
    // Per-task entries: emit each changed leaf as a dotted path so on-disk
    // config stays minimal.
    const beforeTasks = (initialConfig.taskConfig ?? {}) as Record<string, Record<string, unknown>>;
    const afterTasks = (cfg.taskConfig ?? {}) as Record<string, Record<string, unknown>>;
    const allTaskIds = new Set<string>([...Object.keys(beforeTasks), ...Object.keys(afterTasks)]);
    for (const taskId of allTaskIds) {
      const b = beforeTasks[taskId] ?? {};
      const a = afterTasks[taskId] ?? {};
      const allKeys = new Set<string>([...Object.keys(b), ...Object.keys(a)]);
      for (const k of allKeys) {
        if (!deepEqual(b[k], a[k])) {
          entries.push({ path: `taskConfig.${taskId}.${k}`, value: a[k] });
        }
      }
    }
    onComplete(entries);
  }

  // ── Value-editor commit/cancel ───────────────────────────────────────
  function handleEditSubmit(next: unknown): void {
    if (!editingDescriptor) {
      setEditingPath(null);
      return;
    }
    setCfg(
      (prev) =>
        setValueAtPath(
          prev as unknown as Record<string, unknown>,
          editingDescriptor.path,
          next,
        ) as unknown as KuzushiConfig,
    );
    setEditingPath(null);
  }

  function handleEditCancel(): void {
    setEditingPath(null);
  }

  const width = terminalCardWidth();
  const drillTitle = drill ? `Configuration → taskConfig.${drill.taskId}` : "Configuration";
  const dirty = rows.length > 0 || drill ? !deepEqual(initialConfig, cfg) : false;

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxHeader(drillTitle, width)}</Text>
      <Box paddingLeft={SPACING.md}>
        <Text>
          {tokens.muted(
            `Source: ${cfgPath}${dirty ? "  •  " + tokens.warn("unsaved changes") : ""}`,
          )}
        </Text>
      </Box>
      <Text>{""}</Text>

      {drill ? (
        <DrillView rows={drillRows} cursor={safeCursor} />
      ) : (
        <MainView rows={rows} cursor={safeCursor} />
      )}

      {editingDescriptor && (
        <Box marginTop={SPACING.sm}>
          <ValueEditorSwitch
            descriptor={editingDescriptor}
            value={editingValue}
            onSubmit={handleEditSubmit}
            onCancel={handleEditCancel}
          />
        </Box>
      )}

      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}

// ── Sub-views ─────────────────────────────────────────────────────────

function MainView({ rows, cursor }: { rows: Row[]; cursor: number }): React.ReactElement {
  return (
    <Box flexDirection="column">
      {rows.map((row, i) => {
        const isCursor = i === cursor;
        const cur = isCursor ? tokens.accent(">") : " ";
        if (row.kind === "section") {
          const caret = row.expanded ? "▾" : "▸";
          const title = isCursor ? tokens.strong(row.title) : tokens.label(row.title);
          return (
            <Text key={`s-${row.section}`}>
              {cur} {tokens.accent(caret)} {title} {tokens.muted(`(${row.childCount} fields)`)}
            </Text>
          );
        }
        if (row.kind === "field") {
          const lbl = isCursor
            ? tokens.strong(row.descriptor.label)
            : tokens.value(row.descriptor.label);
          return (
            <Box key={`f-${row.descriptor.path}`} flexDirection="column">
              <Text>
                {cur} {lbl} {tokens.muted("=")} {formatValue(row.value, row.descriptor.label)}
              </Text>
              {isCursor ? (
                <Text>
                  {"      "}
                  {tokens.hint(row.descriptor.description)}
                </Text>
              ) : null}
            </Box>
          );
        }
        if (row.kind === "task") {
          const lbl = isCursor ? tokens.strong(row.taskId) : tokens.value(row.taskId);
          return (
            <Text key={`t-${row.taskId}`}>
              {cur} {tokens.accent("▸")} {lbl} {tokens.muted(`(${row.childCount} keys)`)}
            </Text>
          );
        }
        // other
        const lbl = isCursor ? tokens.strong(row.topKey) : tokens.value(row.topKey);
        return (
          <Text key={`o-${row.topKey}`}>
            {cur} {lbl} {tokens.muted("=")} {formatValue(row.value, row.topKey)}
          </Text>
        );
      })}
    </Box>
  );
}

function DrillView({ rows, cursor }: { rows: DrillRow[]; cursor: number }): React.ReactElement {
  return (
    <Box flexDirection="column">
      {rows.map((row, i) => {
        const isCursor = i === cursor;
        const cur = isCursor ? tokens.accent(">") : " ";
        if (row.kind === "back") {
          const lbl = isCursor ? tokens.strong("← back") : tokens.muted("← back");
          return (
            <Text key="back">
              {cur} {lbl}
            </Text>
          );
        }
        const lbl = isCursor
          ? tokens.strong(row.descriptor.label)
          : tokens.value(row.descriptor.label);
        return (
          <Text key={row.descriptor.path}>
            {cur} {lbl} {tokens.muted("=")} {formatValue(row.value, row.descriptor.label)}
          </Text>
        );
      })}
    </Box>
  );
}

// ── Value editor switch ───────────────────────────────────────────────

function ValueEditorSwitch({
  descriptor,
  value,
  onSubmit,
  onCancel,
}: {
  descriptor: FieldDescriptor;
  value: unknown;
  onSubmit: (v: unknown) => void;
  onCancel: () => void;
}): React.ReactElement {
  const t: FieldType = descriptor.type;
  if (t.kind === "bool") {
    return (
      <BoolEditor
        descriptor={descriptor}
        currentValue={value}
        onSubmit={onSubmit}
        onCancel={onCancel}
      />
    );
  }
  if (t.kind === "enum") {
    return (
      <EnumEditor
        descriptor={descriptor}
        currentValue={value}
        onSubmit={onSubmit}
        onCancel={onCancel}
        values={t.values}
        multi={t.multi === true}
      />
    );
  }
  if (t.kind === "number") {
    return (
      <NumberEditor
        descriptor={descriptor}
        currentValue={value}
        onSubmit={onSubmit}
        onCancel={onCancel}
        spec={t}
      />
    );
  }
  if (t.kind === "stringList") {
    return (
      <StringListEditor
        descriptor={descriptor}
        currentValue={value}
        onSubmit={onSubmit}
        onCancel={onCancel}
      />
    );
  }
  if (t.kind === "object") {
    return (
      <Box paddingLeft={SPACING.md}>
        <Text>{tokens.muted("(object — drill down or edit raw JSON via /config raw)")}</Text>
      </Box>
    );
  }
  return (
    <StringEditor
      descriptor={descriptor}
      currentValue={value}
      onSubmit={onSubmit}
      onCancel={onCancel}
      spec={t}
    />
  );
}

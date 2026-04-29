/**
 * Per-type value editors used by ConfigEditor.
 *
 * Each editor is a self-contained Ink component that scopes input to a single
 * field, validates the value, and calls `onSubmit(newValue)` or `onCancel()`.
 * Keybindings are surfaced through `useRegisterKeybindings` so the shell
 * footer reflects what the user can press right now.
 */
import { Box, Text, useInput } from "ink";
import type React from "react";
import { useState } from "react";
import { useBoundedIndex } from "../hooks/useBoundedIndex.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { isCancelInput } from "../interaction-key-policy.js";
import { TextInput } from "../primitives/TextInput.js";
import { SPACING, tokens } from "../tokens.js";
import type { FieldDescriptor, FieldType } from "./ConfigEditor.fields.js";

export interface ValueEditorProps {
  descriptor: FieldDescriptor;
  currentValue: unknown;
  onSubmit: (next: unknown) => void;
  onCancel: () => void;
}

// ── Bool ─────────────────────────────────────────────────────────────────

export function BoolEditor({
  descriptor,
  currentValue,
  onSubmit,
  onCancel,
}: ValueEditorProps): React.ReactElement {
  const [value, setValue] = useState<boolean>(currentValue === true);
  useRegisterKeybindings([
    { keys: "Space", label: "Toggle" },
    { keys: "Enter", label: "Save" },
    { keys: "Esc", label: "Cancel" },
  ]);
  useInput((input, key) => {
    if (isCancelInput(input, key)) onCancel();
    else if (key.return) onSubmit(value);
    else if (input === " ") setValue((v) => !v);
  });
  return (
    <Box flexDirection="column" paddingLeft={SPACING.md}>
      <Text>
        {tokens.label(descriptor.label)} {tokens.muted("=")}{" "}
        {value ? tokens.success("true") : tokens.danger("false")}
      </Text>
    </Box>
  );
}

// ── Enum (single + multi) ───────────────────────────────────────────────

interface EnumEditorProps extends ValueEditorProps {
  values: ReadonlyArray<string>;
  multi: boolean;
}

export function EnumEditor({
  descriptor,
  currentValue,
  onSubmit,
  onCancel,
  values,
  multi,
}: EnumEditorProps): React.ReactElement {
  const initialSelected = new Set<string>(
    multi
      ? Array.isArray(currentValue)
        ? (currentValue as unknown[]).map(String)
        : []
      : typeof currentValue === "string"
        ? [currentValue]
        : [],
  );
  const [selected, setSelected] = useState<Set<string>>(initialSelected);
  const initialIdx = Math.max(
    0,
    values.findIndex((v) => selected.has(v)),
  );
  const nav = useBoundedIndex(values.length, { initial: initialIdx, wrap: true });
  useRegisterKeybindings(
    multi
      ? [
          { keys: "↑/↓", label: "Navigate" },
          { keys: "Space", label: "Toggle" },
          { keys: "Enter", label: "Save" },
          { keys: "Esc", label: "Cancel" },
        ]
      : [
          { keys: "↑/↓", label: "Navigate" },
          { keys: "Enter", label: "Select" },
          { keys: "Esc", label: "Cancel" },
        ],
  );
  useInput((input, key) => {
    if (isCancelInput(input, key)) {
      onCancel();
      return;
    }
    if (multi) {
      if (input === " ") {
        const cur = values[nav.index];
        if (!cur) return;
        setSelected((prev) => {
          const next = new Set(prev);
          if (next.has(cur)) next.delete(cur);
          else next.add(cur);
          return next;
        });
        return;
      }
      if (key.return) {
        onSubmit([...selected]);
        return;
      }
    } else {
      if (key.return) {
        const cur = values[nav.index];
        if (cur !== undefined) onSubmit(cur);
      }
    }
  });
  return (
    <Box flexDirection="column" paddingLeft={SPACING.md}>
      <Text>{tokens.label(descriptor.label)}</Text>
      {values.map((v, i) => {
        const isCursor = i === nav.index;
        const cursor = isCursor ? tokens.focus("❯") : " ";
        const mark = multi
          ? selected.has(v)
            ? tokens.success("[x]")
            : tokens.muted("[ ]")
          : isCursor
            ? tokens.accent("•")
            : " ";
        const line = `${cursor} ${mark} ${v}`;
        return <Text key={v}>{isCursor ? tokens.selection(line) : line}</Text>;
      })}
    </Box>
  );
}

// ── Number ───────────────────────────────────────────────────────────────

interface NumericEditorProps extends ValueEditorProps {
  spec: Extract<FieldType, { kind: "number" }>;
}

export function NumberEditor({
  descriptor,
  currentValue,
  onSubmit,
  onCancel,
  spec,
}: NumericEditorProps): React.ReactElement {
  const [buffer, setBuffer] = useState<string>(currentValue == null ? "" : String(currentValue));
  const [error, setError] = useState<string | null>(null);
  useRegisterKeybindings([
    { keys: "Enter", label: "Save" },
    { keys: "Esc", label: "Cancel" },
    ...(spec.nullable ? [{ keys: "Ctrl+U", label: "Clear (null)", secondary: true }] : []),
  ]);
  const commit = (raw: string) => {
    const trimmed = raw.trim();
    if (trimmed === "" && spec.nullable) {
      onSubmit(null);
      return;
    }
    const n = Number(trimmed);
    if (!Number.isFinite(n)) {
      setError("Must be a number.");
      return;
    }
    if (spec.min != null && n < spec.min) {
      setError(`Must be >= ${spec.min}.`);
      return;
    }
    if (spec.max != null && n > spec.max) {
      setError(`Must be <= ${spec.max}.`);
      return;
    }
    onSubmit(spec.integer ? Math.floor(n) : n);
  };
  return (
    <Box flexDirection="column" paddingLeft={SPACING.md}>
      <Text>{tokens.label(descriptor.label)}</Text>
      <TextInput
        value={buffer}
        onChange={setBuffer}
        onSubmit={commit}
        onCancel={onCancel}
        placeholder={spec.nullable ? "(empty = null)" : "(number)"}
      />
      {error ? <Text>{tokens.danger(error)}</Text> : null}
    </Box>
  );
}

// ── String ───────────────────────────────────────────────────────────────

interface StringEditorProps extends ValueEditorProps {
  spec: Extract<FieldType, { kind: "string" }>;
}

export function StringEditor({
  descriptor,
  currentValue,
  onSubmit,
  onCancel,
  spec,
}: StringEditorProps): React.ReactElement {
  const [buffer, setBuffer] = useState<string>(
    typeof currentValue === "string" ? currentValue : "",
  );
  useRegisterKeybindings([
    { keys: "Enter", label: "Save" },
    { keys: "Esc", label: "Cancel" },
  ]);
  const commit = (raw: string) => {
    const trimmed = raw.trim();
    if (trimmed === "" && spec.optional) {
      onSubmit(undefined);
      return;
    }
    onSubmit(trimmed);
  };
  return (
    <Box flexDirection="column" paddingLeft={SPACING.md}>
      <Text>{tokens.label(descriptor.label)}</Text>
      <TextInput
        value={buffer}
        onChange={setBuffer}
        onSubmit={commit}
        onCancel={onCancel}
        placeholder={spec.optional ? "(empty = unset)" : "(string)"}
      />
    </Box>
  );
}

// ── String list ─────────────────────────────────────────────────────────

export function StringListEditor({
  descriptor,
  currentValue,
  onSubmit,
  onCancel,
}: ValueEditorProps): React.ReactElement {
  const initial: string[] = Array.isArray(currentValue)
    ? (currentValue as unknown[]).map(String)
    : [];
  const [items, setItems] = useState<string[]>(initial);
  const [mode, setMode] = useState<"nav" | "edit" | "add">("nav");
  const [buffer, setBuffer] = useState<string>("");
  const nav = useBoundedIndex(Math.max(items.length, 1), { isActive: mode === "nav", wrap: true });

  useRegisterKeybindings(
    mode === "nav"
      ? [
          { keys: "↑/↓", label: "Navigate" },
          { keys: "a", label: "Add" },
          { keys: "e", label: "Edit" },
          { keys: "d", label: "Delete" },
          { keys: "s", label: "Save" },
          { keys: "Esc", label: "Cancel" },
        ]
      : [
          { keys: "Enter", label: "Save item" },
          { keys: "Esc", label: "Discard item" },
        ],
  );

  useInput(
    (input, key) => {
      if (mode !== "nav") return;
      if (isCancelInput(input, key)) {
        onCancel();
      } else if (input === "a") {
        setBuffer("");
        setMode("add");
      } else if (input === "e" && items.length > 0) {
        setBuffer(items[nav.index] ?? "");
        setMode("edit");
      } else if (input === "d" && items.length > 0) {
        const next = [...items];
        next.splice(nav.index, 1);
        setItems(next);
      } else if (input === "s") {
        onSubmit(items);
      }
    },
    { isActive: mode === "nav" },
  );

  const commit = (raw: string) => {
    const trimmed = raw.trim();
    if (trimmed === "") {
      setMode("nav");
      setBuffer("");
      return;
    }
    if (mode === "add") {
      setItems((prev) => [...prev, trimmed]);
    } else if (mode === "edit") {
      setItems((prev) => {
        const next = [...prev];
        next[nav.index] = trimmed;
        return next;
      });
    }
    setMode("nav");
    setBuffer("");
  };

  return (
    <Box flexDirection="column" paddingLeft={SPACING.md}>
      <Text>
        {tokens.label(descriptor.label)}{" "}
        {tokens.muted(`(${items.length} item${items.length === 1 ? "" : "s"})`)}
      </Text>
      {items.length === 0 ? (
        <Text>{tokens.muted("  (empty)")}</Text>
      ) : (
        items.map((item, i) => {
          const isCursor = mode === "nav" && i === nav.index;
          const cursor = isCursor ? tokens.focus("❯") : " ";
          const line = `${cursor} ${item}`;
          // biome-ignore lint/suspicious/noArrayIndexKey: string-list editor allows duplicate values and never reorders rows.
          return <Text key={`${i}-${item}`}>{isCursor ? tokens.selection(line) : line}</Text>;
        })
      )}
      {mode !== "nav" && (
        <Box marginTop={SPACING.sm}>
          <Text>{tokens.accent(mode === "add" ? "Add: " : "Edit: ")}</Text>
          <TextInput
            value={buffer}
            onChange={setBuffer}
            onSubmit={commit}
            onCancel={() => {
              setMode("nav");
              setBuffer("");
            }}
            prefix=""
          />
        </Box>
      )}
    </Box>
  );
}

/**
 * MultiSelect — vertical keyboard-navigable list with per-row checkbox state.
 *
 * The companion to {@link SelectList} for surfaces where the operator picks
 * a *set* (model pool, finding filters, etc.) rather than a single value.
 *
 * Keymap:
 *   - ↑/↓ or k/j — move the cursor
 *   - Space      — toggle the highlighted row
 *   - a          — select all enabled rows
 *   - n          — clear selection
 *   - Enter      — confirm; rejected when `selectedIds.size < (minSelected ?? 0)`
 *   - Esc / ^C   — cancel
 *
 * State is controlled — the parent owns the `Set<T>` and reacts to
 * `onToggle` / `onConfirm`. This matches the existing primitive style and
 * keeps persistence (config file writes) on the parent's side.
 */
import { Box, Text, useInput } from "ink";
import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { isCancelInput } from "../interaction-key-policy.js";
import { useLayoutContext } from "../layout-context.js";
import { tokens } from "../tokens.js";
import type { SelectListItem } from "./SelectList.js";

export type { SelectListItem } from "./SelectList.js";

export interface MultiSelectRenderContext<T> {
  item: SelectListItem<T>;
  isCursor: boolean;
  isSelected: boolean;
  cursor: string;
  cursorPrefix: string;
  /** Pre-rendered checkbox glyph: `[✓]` selected, `[ ]` unselected. */
  checkbox: string;
}

export interface MultiSelectRowAction<T> {
  /** Single-character trigger; matched against Ink's `input`. */
  key: string;
  /** Short label used in optional footer hints. */
  label: string;
  /** Invoked with the *highlighted* row's id. */
  onAction: (id: T) => void;
}

export interface MultiSelectProps<T> {
  items: ReadonlyArray<SelectListItem<T>>;
  /** Controlled selection set. */
  selectedIds: ReadonlySet<T>;
  /** Toggle one id (Space). */
  onToggle: (id: T) => void;
  /** Bulk replace (a / n). Optional — when omitted, those keys no-op. */
  onReplaceAll?: (ids: ReadonlySet<T>) => void;
  /** Confirm with the current selection (Enter). */
  onConfirm: (ids: ReadonlySet<T>) => void;
  onCancel?: () => void;
  onHighlight?: (id: T) => void;
  isActive?: boolean;
  cursor?: string;
  cursorColor?: (s: string) => string;
  emptyMessage?: string;
  showPosition?: boolean;
  /**
   * Minimum selection size for Enter to fire `onConfirm`. Defaults to `0`.
   * When unmet, Enter is a no-op and the position line surfaces a hint.
   */
  minSelected?: number;
  /**
   * Power-user keys triggered on the *highlighted* row. Used by the model
   * editor to bind `d` → "set as default", etc.
   */
  rowActions?: ReadonlyArray<MultiSelectRowAction<T>>;
  renderItem?: (ctx: MultiSelectRenderContext<T>) => ReactNode;
}

const CHECKBOX_ON = "[✓]"; // [✓]
const CHECKBOX_OFF = "[ ]";

/**
 * Step the cursor to the next non-disabled row in `direction`. Mirrors the
 * helper in {@link SelectList} but exposed here as a pure function so the
 * navigation behavior stays testable without an Ink render.
 */
export function nextEnabledIndex<T>(
  items: ReadonlyArray<SelectListItem<T>>,
  from: number,
  direction: 1 | -1,
): number {
  if (items.length === 0) return 0;
  let i = from;
  for (let steps = 0; steps < items.length; steps++) {
    i = (i + direction + items.length) % items.length;
    if (!items[i]?.disabled) return i;
  }
  return from;
}

/** Return `selectedIds` with `id` toggled. Pure; safe to test in isolation. */
export function toggleSelection<T>(selectedIds: ReadonlySet<T>, id: T): Set<T> {
  const next = new Set(selectedIds);
  if (next.has(id)) {
    next.delete(id);
  } else {
    next.add(id);
  }
  return next;
}

/** Set containing every enabled row's id. */
export function selectAllIds<T>(items: ReadonlyArray<SelectListItem<T>>): Set<T> {
  const next = new Set<T>();
  for (const item of items) {
    if (!item.disabled) next.add(item.id);
  }
  return next;
}

export function MultiSelect<T = string>(props: MultiSelectProps<T>): JSX.Element {
  const {
    items,
    selectedIds,
    onToggle,
    onReplaceAll,
    onConfirm,
    onCancel,
    onHighlight,
    isActive = true,
    cursorColor = tokens.accent,
    emptyMessage,
    showPosition = true,
    minSelected = 0,
    rowActions,
    renderItem,
  } = props;
  const { theme } = useLayoutContext();
  const resolvedCursor = props.cursor ?? theme.glyphs.selection;

  const initialIndex = useMemo(() => items.findIndex((it) => !it.disabled), [items]);

  const [cursorIdx, setCursorIdx] = useState<number>(Math.max(0, initialIndex));

  useEffect(() => {
    if (cursorIdx >= items.length) {
      setCursorIdx(Math.max(0, items.length - 1));
    }
  }, [cursorIdx, items.length]);

  const highlight = useCallback(
    (next: number) => {
      setCursorIdx(next);
      const item = items[next];
      if (item) onHighlight?.(item.id);
    },
    [items, onHighlight],
  );

  useInput(
    (input, key) => {
      if (isCancelInput(input, key)) {
        onCancel?.();
        return;
      }
      if (items.length === 0) return;

      if (key.upArrow || input === "k") {
        highlight(nextEnabledIndex(items, cursorIdx, -1));
        return;
      }
      if (key.downArrow || input === "j") {
        highlight(nextEnabledIndex(items, cursorIdx, 1));
        return;
      }
      if (input === " ") {
        const item = items[cursorIdx];
        if (item && !item.disabled) onToggle(item.id);
        return;
      }
      if (input === "a" && onReplaceAll) {
        onReplaceAll(selectAllIds(items));
        return;
      }
      if (input === "n" && onReplaceAll) {
        onReplaceAll(new Set<T>());
        return;
      }
      if (key.return) {
        if (selectedIds.size < minSelected) return;
        onConfirm(selectedIds);
        return;
      }
      if (input && rowActions && rowActions.length > 0) {
        const action = rowActions.find((a) => a.key === input);
        if (action) {
          const item = items[cursorIdx];
          if (item && !item.disabled) action.onAction(item.id);
        }
      }
    },
    { isActive },
  );

  if (items.length === 0) {
    return (
      <Box>
        <Text>{tokens.muted(emptyMessage ?? "(no options)")}</Text>
      </Box>
    );
  }

  const cursorPrefixBlank = " ".repeat(resolvedCursor.length);
  const belowMin = selectedIds.size < minSelected;

  return (
    <Box flexDirection="column">
      {showPosition && items.length > 1 ? (
        <Text>
          {tokens.hint(`(${cursorIdx + 1} of ${items.length} · ${selectedIds.size} selected)`)}
          {cursorIdx > 0 ? tokens.hint(" ▲") : ""}
          {cursorIdx < items.length - 1 ? tokens.hint(" ▼") : ""}
          {belowMin ? tokens.warn(`  pick ≥ ${minSelected} to continue`) : ""}
        </Text>
      ) : null}
      {items.map((item, idx) => {
        const isCursor = idx === cursorIdx;
        const isSelected = selectedIds.has(item.id);
        const cursorPrefix = isCursor ? cursorColor(resolvedCursor) : cursorPrefixBlank;
        const checkbox = isSelected ? tokens.success(CHECKBOX_ON) : CHECKBOX_OFF;
        if (renderItem) {
          return (
            <Box key={String(item.id)} flexDirection="column">
              {renderItem({
                item,
                isCursor,
                isSelected,
                cursor: resolvedCursor,
                cursorPrefix,
                checkbox,
              })}
            </Box>
          );
        }
        const label = item.disabled ? tokens.muted(item.label) : item.label;
        const detail = item.detail ? ` ${tokens.subtle(item.detail)}` : "";
        const line = `${cursorPrefix} ${checkbox} ${label}${detail}`;
        return (
          <Box key={String(item.id)} flexDirection="row">
            <Text>{isCursor && !item.disabled ? tokens.selection(line) : line}</Text>
          </Box>
        );
      })}
    </Box>
  );
}

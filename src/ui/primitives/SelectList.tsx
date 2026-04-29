/**
 * SelectList — vertical keyboard-navigable list with a visible cursor.
 *
 * Consolidates the bespoke bounded-index + arrow-nav implementations in
 * SetupWizard, CredentialPrompt, ContextIntake, ThreatModelEditor.
 *
 * Supports a `renderItem` prop for components that need more than a single
 * label+detail line per row (e.g. selected-row shows an expanded summary).
 */
import { Box, Text, useInput } from "ink";
import type { ReactNode } from "react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { icons } from "../icons.js";
import { isCancelInput } from "../interaction-key-policy.js";
import { useLayoutContext } from "../layout-context.js";
import { tokens } from "../tokens.js";

export interface SelectListItem<T = string> {
  id: T;
  label: string;
  detail?: string;
  disabled?: boolean;
}

export interface SelectListRenderContext<T> {
  item: SelectListItem<T>;
  isCursor: boolean;
  cursor: string;
  cursorPrefix: string;
}

export interface SelectListProps<T> {
  items: ReadonlyArray<SelectListItem<T>>;
  selectedId?: T;
  onSelect: (id: T) => void;
  onHighlight?: (id: T) => void;
  onCancel?: () => void;
  isActive?: boolean;
  cursor?: string;
  cursorColor?: (s: string) => string;
  emptyMessage?: string;
  showPosition?: boolean;
  /**
   * Custom row renderer. Receives the item plus cursor/highlight state and
   * returns a React node (typically a Box). When omitted, the default
   * `<cursor> <label> <detail>` layout is used.
   */
  renderItem?: (ctx: SelectListRenderContext<T>) => ReactNode;
}

function nextEnabled<T>(
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

export function SelectList<T = string>(props: SelectListProps<T>): JSX.Element {
  const {
    items,
    selectedId,
    onSelect,
    onHighlight,
    onCancel,
    isActive = true,
    cursorColor = tokens.accent,
    emptyMessage,
    showPosition = true,
    renderItem,
  } = props;
  const { theme } = useLayoutContext();
  const resolvedCursor = props.cursor ?? theme.glyphs.selection;

  const initialIndex = useMemo(() => {
    if (selectedId === undefined) return 0;
    const idx = items.findIndex((it) => it.id === selectedId);
    return idx >= 0 ? idx : 0;
  }, [items, selectedId]);

  const [cursorIdx, setCursorIdx] = useState<number>(initialIndex);

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
        highlight(nextEnabled(items, cursorIdx, -1));
      } else if (key.downArrow || input === "j") {
        highlight(nextEnabled(items, cursorIdx, 1));
      } else if (key.return) {
        const item = items[cursorIdx];
        if (item && !item.disabled) onSelect(item.id);
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

  return (
    <Box flexDirection="column">
      {showPosition && items.length > 1 ? (
        <Text>
          {tokens.hint(`(${cursorIdx + 1} of ${items.length})`)}
          {cursorIdx > 0 ? tokens.hint(" ▲") : ""}
          {cursorIdx < items.length - 1 ? tokens.hint(" ▼") : ""}
        </Text>
      ) : null}
      {items.map((item, idx) => {
        const isCursor = idx === cursorIdx;
        const cursorPrefix = isCursor ? cursorColor(resolvedCursor) : cursorPrefixBlank;
        if (renderItem) {
          return (
            <Box key={String(item.id)} flexDirection="column">
              {renderItem({ item, isCursor, cursor: resolvedCursor, cursorPrefix })}
            </Box>
          );
        }
        const label = item.disabled ? tokens.muted(item.label) : item.label;
        const detail = item.detail ? ` ${tokens.subtle(item.detail)}` : "";
        const line = `${cursorPrefix} ${label}${detail}`;
        return (
          <Box key={String(item.id)} flexDirection="row">
            <Text>{isCursor && !item.disabled ? tokens.selection(line) : line}</Text>
          </Box>
        );
      })}
      {isActive ? null : <Text>{tokens.hint(`  ${icons.dot} inactive`)}</Text>}
    </Box>
  );
}

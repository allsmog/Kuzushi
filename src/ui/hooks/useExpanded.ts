/**
 * useExpanded — toggle a collapsed/expanded boolean via Space or Enter.
 *
 * Powers ExpandableSection. Extracted so consumers can also drive their own
 * custom expander UIs without rebuilding the key handling.
 */
import { useInput } from "ink";
import { useCallback, useRef, useState } from "react";

export interface UseExpandedOptions {
  initial?: boolean;
  isActive?: boolean;
  onChange?: (expanded: boolean) => void;
}

export interface UseExpandedResult {
  expanded: boolean;
  toggle: () => void;
  expand: () => void;
  collapse: () => void;
}

export function useExpanded(
  options: UseExpandedOptions = {},
): UseExpandedResult {
  const { initial = false, isActive = true, onChange } = options;
  const [expanded, setExpanded] = useState<boolean>(initial);
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;

  const updateIfChanged = useCallback((next: boolean) => {
    setExpanded((prev) => {
      if (prev !== next) onChangeRef.current?.(next);
      return next;
    });
  }, []);

  const toggle = useCallback(() => {
    setExpanded((prev) => {
      onChangeRef.current?.(!prev);
      return !prev;
    });
  }, []);

  useInput(
    (input, key) => {
      if (input === " " || key.return) toggle();
    },
    { isActive },
  );

  return {
    expanded,
    toggle,
    expand: useCallback(() => updateIfChanged(true), [updateIfChanged]),
    collapse: useCallback(() => updateIfChanged(false), [updateIfChanged]),
  };
}

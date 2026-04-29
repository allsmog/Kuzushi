/**
 * DelayedBusyIndicator — Norman-style feedback for work that lasts long
 * enough to feel blocked.
 *
 * It stays silent for the first 100ms by default to avoid flashing on
 * immediate commands, then shows a spinner, elapsed time, and cancel hint.
 */

import { Box, Text } from "ink";
import React from "react";
import { formatDuration, truncateEnd } from "../format.js";
import { useElapsed } from "../hooks.js";
import { SPACING, tokens } from "../tokens.js";
import { Spinner } from "./Spinner.js";

interface DelayedBusyIndicatorProps {
  label: string;
  detail?: string;
  cancelHint?: string;
  startedAt?: number;
  delayMs?: number;
}

export function DelayedBusyIndicator({
  label,
  detail,
  cancelHint = "Ctrl+C interrupt",
  startedAt,
  delayMs = 100,
}: DelayedBusyIndicatorProps): React.ReactElement | null {
  const startRef = React.useRef(startedAt ?? Date.now());
  const [visible, setVisible] = React.useState(delayMs <= 0);
  const elapsedMs = useElapsed(startRef.current, 1000);

  React.useEffect(() => {
    if (delayMs <= 0) {
      setVisible(true);
      return;
    }
    const timer = setTimeout(() => setVisible(true), delayMs);
    return () => clearTimeout(timer);
  }, [delayMs]);

  if (!visible) return null;

  const elapsed = formatDuration(elapsedMs);
  const renderedDetail = detail ? truncateEnd(detail, 96) : "No output yet. Still running.";

  return (
    <Box flexDirection="column" marginTop={SPACING.sm} paddingLeft={SPACING.md}>
      <Box>
        <Spinner color="accent" />
        <Text>
          {" "}
          {tokens.strong(label)}
          {tokens.muted(` · ${elapsed}`)}
        </Text>
      </Box>
      <Box paddingLeft={SPACING.md}>
        <Text>{tokens.muted(renderedDetail)}</Text>
      </Box>
      {cancelHint ? (
        <Box paddingLeft={SPACING.md}>
          <Text>{tokens.hint(cancelHint)}</Text>
        </Box>
      ) : null}
    </Box>
  );
}

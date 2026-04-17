/**
 * Rich error display with category badge, dimmed frame list, and an
 * actionable "Next Step" call-to-action.
 *
 * Now delegates classification to `src/ui/error-format.ts` so the logic is
 * shared across UI surfaces and the orchestrator's error-reporting paths.
 */

import { Box, Text } from "ink";
import type React from "react";
import {
  classifyError,
  type ErrorCategory,
  formatError,
  suggestNextStep,
} from "../error-format.js";
import { badge } from "../format.js";
import { icons } from "../icons.js";
import { tokens } from "../tokens.js";

const CATEGORY_BADGES: Record<ErrorCategory, string> = {
  rate_limit: badge("RATE LIMIT", "yellow"),
  auth: badge("AUTH", "red"),
  budget: badge("BUDGET", "yellow"),
  transient: badge("TRANSIENT", "cyan"),
  validation: badge("VALIDATION", "magenta"),
  fatal: badge("FATAL", "red"),
  unknown: badge("ERROR", "red"),
};

/** Legacy hint kept as a fallback when `suggestNextStep` returns undefined. */
const CATEGORY_FALLBACK_HINTS: Record<ErrorCategory, string> = {
  rate_limit: "Backing off, will retry automatically",
  auth: "Check ANTHROPIC_API_KEY environment variable or --api-key flag",
  budget: "Pipeline stopped — increase --budget or remove the limit",
  transient: "Will retry automatically",
  validation: "Check your configuration and input",
  fatal: "Pipeline cannot continue",
  unknown: "",
};

interface ErrorCardProps {
  message: string;
  category?: ErrorCategory;
  attempts?: number;
  maxAttempts?: number;
  /**
   * Optional raw error value. When provided, frames from its stack are
   * rendered in a dim sub-list (capped at 3) so operators can orient
   * themselves without needing `--debug`.
   */
  error?: unknown;
  /** Show full stack trace. Gated upstream by `--debug`. */
  showStack?: boolean;
}

export function ErrorCard({
  message,
  category,
  attempts,
  maxAttempts,
  error,
  showStack = false,
}: ErrorCardProps): React.ReactElement {
  const resolvedCategory: ErrorCategory =
    category ?? (error != null ? classifyError(error) : "unknown");
  const categoryBadge = CATEGORY_BADGES[resolvedCategory];
  const nextStep =
    suggestNextStep(error, resolvedCategory) ??
    CATEGORY_FALLBACK_HINTS[resolvedCategory];
  const retryInfo =
    attempts && maxAttempts
      ? tokens.muted(` (attempt ${attempts}/${maxAttempts})`)
      : attempts && attempts > 1
        ? tokens.muted(` (attempt ${attempts})`)
        : "";

  const formatted = error != null ? formatError(error, { maxFrames: 3, includeRaw: showStack }) : null;
  const frames = formatted?.frames ?? [];

  return (
    <Box flexDirection="column">
      <Box paddingLeft={2}>
        <Text>
          {categoryBadge} {tokens.strong(message)}
          {retryInfo}
        </Text>
      </Box>
      {frames.length > 0 ? (
        <Box flexDirection="column" paddingLeft={4}>
          {frames.map((frame, i) => (
            <Text key={`frame-${i}`}>
              {tokens.muted(
                `${icons.treeMiddle} ${frame.file}${frame.line ? `:${frame.line}` : ""}`,
              )}
            </Text>
          ))}
        </Box>
      ) : null}
      {nextStep ? (
        <Box paddingLeft={2} marginTop={1}>
          <Text>
            {tokens.successStrong("Next step:")} {nextStep}
          </Text>
        </Box>
      ) : null}
      {showStack && formatted?.raw ? (
        <Box flexDirection="column" paddingLeft={4} marginTop={1}>
          {formatted.raw.split("\n").map((line, i) => (
            <Text key={`raw-${i}`}>{tokens.subtle(line)}</Text>
          ))}
        </Box>
      ) : null}
    </Box>
  );
}

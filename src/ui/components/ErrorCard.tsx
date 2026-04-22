/**
 * Rich error display with category badge, dimmed frame list, and an
 * actionable "Next Step" call-to-action.
 *
 * Classification is delegated to `src/ui/error-format.ts` so the logic
 * stays shared across UI surfaces and the orchestrator's error-reporting
 * paths.
 *
 * Workstream 3 widened the props surface so tool-failure call sites can
 * pass an explicit `{ code, hint }` pair instead of re-deriving them.
 * When supplied, `code` replaces the category-derived badge and `hint`
 * replaces `suggestNextStep`, so the shell can keep known-error copy
 * close to the orchestrator throw site.
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
import { SPACING, tokens } from "../tokens.js";

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
  /**
   * Optional short error code ("E_AUTH", "E_TOOL_TIMEOUT", etc). When set
   * it's rendered inside a `[code]` prefix in front of the badge so
   * operators can grep server logs / docs.
   */
  code?: string;
  /**
   * Explicit recovery hint. Overrides `suggestNextStep`. Use when the
   * throw site knows more than `classifyError` can infer (e.g. it knows
   * which env var was missing).
   */
  hint?: string;
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
  /**
   * Tool name when rendering a ToolResult-failure card. Surfaces on a
   * second line so the headline stays scannable.
   */
  toolName?: string;
  /**
   * Input summary for the failing tool call (e.g. JSON snippet). Dimmed
   * and truncated so the card stays short.
   */
  toolInput?: string;
}

const TOOL_INPUT_MAX = 96;

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return `${s.slice(0, Math.max(0, max - 1))}…`;
}

export function ErrorCard({
  message,
  category,
  code,
  hint,
  attempts,
  maxAttempts,
  error,
  showStack = false,
  toolName,
  toolInput,
}: ErrorCardProps): React.ReactElement {
  const resolvedCategory: ErrorCategory =
    category ?? (error != null ? classifyError(error) : "unknown");
  const categoryBadge = CATEGORY_BADGES[resolvedCategory];
  const nextStep =
    hint ?? suggestNextStep(error, resolvedCategory) ?? CATEGORY_FALLBACK_HINTS[resolvedCategory];
  const retryInfo =
    attempts && maxAttempts
      ? tokens.muted(` (attempt ${attempts}/${maxAttempts})`)
      : attempts && attempts > 1
        ? tokens.muted(` (attempt ${attempts})`)
        : "";

  const formatted =
    error != null ? formatError(error, { maxFrames: 3, includeRaw: showStack }) : null;
  const frames = formatted?.frames ?? [];

  return (
    <Box flexDirection="column">
      <Box paddingLeft={SPACING.md}>
        <Text>
          {code ? `${tokens.muted(`[${code}]`)} ` : ""}
          {categoryBadge} {tokens.strong(message)}
          {retryInfo}
        </Text>
      </Box>
      {toolName ? (
        <Box paddingLeft={4}>
          <Text>
            {tokens.muted("tool: ")}
            {tokens.value(toolName)}
            {toolInput ? tokens.muted(`   input: ${truncate(toolInput, TOOL_INPUT_MAX)}`) : ""}
          </Text>
        </Box>
      ) : null}
      {frames.length > 0 ? (
        <Box flexDirection="column" paddingLeft={SPACING.xl}>
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
        <Box paddingLeft={SPACING.md} marginTop={SPACING.sm}>
          <Text>
            {tokens.successStrong("Next step:")} {nextStep}
          </Text>
        </Box>
      ) : null}
      {showStack && formatted?.raw ? (
        <Box flexDirection="column" paddingLeft={SPACING.xl} marginTop={SPACING.sm}>
          {formatted.raw.split("\n").map((line, i) => (
            <Text key={`raw-${i}`}>{tokens.subtle(line)}</Text>
          ))}
        </Box>
      ) : null}
    </Box>
  );
}

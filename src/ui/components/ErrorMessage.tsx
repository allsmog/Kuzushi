/**
 * Typed error renderer for shell history — classifies an error string and
 * renders a matching component with actionable hints instead of a plain red
 * text wall.
 *
 * cc-repo has one component per error kind (`RateLimitMessage`,
 * `InvalidApiKeyMessage`, etc.). We roll that into a single dispatcher
 * that pattern-matches the error text and renders the right body. Keeps
 * the surface area small while matching cc-repo's UX — operators see
 * "Context limit reached · /clear to continue" instead of a
 * raw "Error: context window exceeded" string.
 */

import { Box, Text } from "ink";
import type React from "react";
import { tokens } from "../tokens.js";

export type ErrorKind = "rate-limit" | "auth" | "timeout" | "context-limit" | "aborted" | "generic";

/** Heuristic classification — pattern-match against the error text. */
export function classifyError(text: string): ErrorKind {
  const lower = text.toLowerCase();
  if (
    lower.includes("rate limit") ||
    lower.includes("rate-limit") ||
    lower.includes("429") ||
    lower.includes("too many requests")
  ) {
    return "rate-limit";
  }
  if (
    lower.includes("invalid api key") ||
    lower.includes("unauthorized") ||
    lower.includes("401") ||
    lower.includes("authentication") ||
    lower.includes("forbidden") ||
    lower.includes("403")
  ) {
    return "auth";
  }
  if (lower.includes("timeout") || lower.includes("timed out") || lower.includes("etimedout")) {
    return "timeout";
  }
  if (
    lower.includes("context") &&
    (lower.includes("limit") ||
      lower.includes("exceeded") ||
      lower.includes("too long") ||
      lower.includes("window"))
  ) {
    return "context-limit";
  }
  if (
    lower.includes("cancel") ||
    lower.includes("abort") ||
    lower.includes("interrupt") ||
    lower.includes("sigint")
  ) {
    return "aborted";
  }
  return "generic";
}

interface ErrorMessageProps {
  text: string;
  /** Override the heuristic classification. */
  kind?: ErrorKind;
}

/**
 * Dispatch on classified kind. Each kind renders the headline in red +
 * a muted hint line with the recommended remediation.
 */
export function ErrorMessage({ text, kind }: ErrorMessageProps): React.ReactElement {
  const resolved = kind ?? classifyError(text);

  switch (resolved) {
    case "rate-limit":
      return (
        <Box flexDirection="column">
          <Text>{tokens.danger(`Rate limited · ${text}`)}</Text>
          <Text>
            {tokens.muted(
              "Provider throttled this request. Wait a moment and retry, or switch models with /provider.",
            )}
          </Text>
        </Box>
      );
    case "auth":
      return (
        <Box flexDirection="column">
          <Text>{tokens.danger(`Auth failure · ${text}`)}</Text>
          <Text>
            {tokens.muted(
              "API key is missing, expired, or rejected. Run /auth to paste a fresh provider key.",
            )}
          </Text>
        </Box>
      );
    case "timeout":
      return (
        <Box flexDirection="column">
          <Text>{tokens.danger(`Timed out · ${text}`)}</Text>
          <Text>
            {tokens.muted(
              "Upstream took too long. Try a simpler prompt, a smaller target, or set API_TIMEOUT_MS to a higher value.",
            )}
          </Text>
        </Box>
      );
    case "context-limit":
      return (
        <Box flexDirection="column">
          <Text>{tokens.danger(`Context limit reached · ${text}`)}</Text>
          <Text>
            {tokens.muted(
              "Conversation exceeded the model's window. Run /clear to continue with a fresh shell context.",
            )}
          </Text>
        </Box>
      );
    case "aborted":
      // Operator-initiated cancel — render muted (informational), not dangerous.
      return <Text>{tokens.muted(text)}</Text>;
    default:
      return <Text>{tokens.danger(text)}</Text>;
  }
}

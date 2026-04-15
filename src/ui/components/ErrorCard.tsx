/**
 * Rich error display with category badge and contextual hints.
 *
 * Renders:
 *    RATE LIMIT  API rate limit exceeded
 *   Backing off, will retry automatically (attempt 2/3)
 *
 *    AUTH  Invalid API key
 *   Check ANTHROPIC_API_KEY or --api-key flag
 */
import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import { badge } from "../format.js";

export type ErrorCategory = "rate_limit" | "auth" | "budget" | "transient" | "validation" | "fatal" | "unknown";

const CATEGORY_BADGES: Record<ErrorCategory, string> = {
  rate_limit: badge("RATE LIMIT", "yellow"),
  auth: badge("AUTH", "red"),
  budget: badge("BUDGET", "yellow"),
  transient: badge("TRANSIENT", "cyan"),
  validation: badge("VALIDATION", "magenta"),
  fatal: badge("FATAL", "red"),
  unknown: badge("ERROR", "red"),
};

const CATEGORY_HINTS: Record<ErrorCategory, string> = {
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
}

export function ErrorCard({ message, category, attempts, maxAttempts }: ErrorCardProps): React.ReactElement {
  const cat = category ?? "unknown";
  const categoryBadge = CATEGORY_BADGES[cat];
  const hint = CATEGORY_HINTS[cat];
  const retryInfo = attempts && maxAttempts
    ? chalk.dim(` (attempt ${attempts}/${maxAttempts})`)
    : attempts && attempts > 1
      ? chalk.dim(` (attempt ${attempts})`)
      : "";

  return (
    <Box flexDirection="column">
      <Text>{"  "}{categoryBadge}  {message}</Text>
      {(hint || retryInfo) && (
        <Text>{"  "}{chalk.dim(icons.treeLast)} {chalk.dim(hint)}{retryInfo}</Text>
      )}
    </Box>
  );
}

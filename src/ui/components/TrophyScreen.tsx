/**
 * Trophy / completion screen — the memorable ending to a scan.
 *
 * Adapts to results:
 *
 * Clean repo:
 *   ┌──────────────────────────────────────────────────────┐
 *   │                                                      │
 *   │              ✦  ALL CLEAR  ✦                         │
 *   │                                                      │
 *   │    0 true positives across 200 findings              │
 *   │    42 triaged  ·  $1.23  ·  4m 12s                   │
 *   │                                                      │
 *   └──────────────────────────────────────────────────────┘
 *
 * Findings found:
 *   ┌──────────────────────────────────────────────────────┐
 *   │                                                      │
 *   │           ⚠  ACTION REQUIRED  ⚠                      │
 *   │                                                      │
 *   │    3 true positives  ·  2 exploitable                │
 *   │    1 attack chain (CRITICAL)                         │
 *   │                                                      │
 *   │    42 triaged  ·  $2.47  ·  8m 30s                   │
 *   │                                                      │
 *   └──────────────────────────────────────────────────────┘
 */
import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { formatCost, formatDuration } from "../format.js";
import type { SummaryData } from "../state.js";

interface TrophyScreenProps {
  data: SummaryData;
}

const WIDTH = 56;

export function TrophyScreen({ data }: TrophyScreenProps): React.ReactElement {
  const tp = data.verdictCounts.tp;
  const isClean = tp === 0;
  const hasExploitable = data.exploitable > 0;
  const hasChains = data.exploitChains.length > 0;

  const borderChar = isClean ? chalk.green("─") : chalk.red("─");
  const cornerTL = isClean ? chalk.green("┌") : chalk.red("┌");
  const cornerTR = isClean ? chalk.green("┐") : chalk.red("┐");
  const cornerBL = isClean ? chalk.green("└") : chalk.red("└");
  const cornerBR = isClean ? chalk.green("┘") : chalk.red("┘");
  const side = isClean ? chalk.green("│") : chalk.red("│");

  const topBorder = `${cornerTL}${borderChar.repeat(WIDTH)}${cornerTR}`;
  const bottomBorder = `${cornerBL}${borderChar.repeat(WIDTH)}${cornerBR}`;
  const emptyLine = `${side}${" ".repeat(WIDTH)}${side}`;

  // Stats line
  const totalCost = data.triageCostUsd + data.verificationCostUsd + data.pocHarnessCostUsd;
  const duration = data.runMetrics?.durationBreakdown?.total;
  const statsParts = [
    `${data.totalTriaged} triaged`,
    formatCost(totalCost),
  ];
  if (duration) statsParts.push(formatDuration(duration));
  const statsLine = statsParts.join(chalk.dim("  ·  "));

  if (isClean) {
    // ✦ ALL CLEAR ✦
    const headline = chalk.green.bold("✦  ALL CLEAR  ✦");
    const subline = `0 true positives across ${data.totalTriaged} findings`;
    const message = "This repository passed all security checks.";

    return (
      <Box flexDirection="column">
        <Text>{"  "}{topBorder}</Text>
        <Text>{"  "}{emptyLine}</Text>
        <Text>{"  "}{side}{centerPad(headline, WIDTH)}{side}</Text>
        <Text>{"  "}{emptyLine}</Text>
        <Text>{"  "}{side}{centerPad(subline, WIDTH)}{side}</Text>
        <Text>{"  "}{side}{centerPad(statsLine, WIDTH)}{side}</Text>
        <Text>{"  "}{emptyLine}</Text>
        <Text>{"  "}{side}{centerPad(chalk.dim(message), WIDTH)}{side}</Text>
        <Text>{"  "}{emptyLine}</Text>
        <Text>{"  "}{bottomBorder}</Text>
      </Box>
    );
  }

  // ⚠ ACTION REQUIRED ⚠
  const headline = chalk.red.bold("⚠  ACTION REQUIRED  ⚠");
  const mainStat = [
    chalk.red.bold(`${tp} true positive${tp > 1 ? "s" : ""}`),
    hasExploitable ? chalk.red(`${data.exploitable} exploitable`) : null,
  ].filter(Boolean).join(chalk.dim("  ·  "));

  const chainStat = hasChains
    ? `${data.exploitChains.length} attack chain${data.exploitChains.length > 1 ? "s" : ""} (${data.exploitChains.map((c) => c.overallSeverity).join(", ")})`
    : null;

  const needsReview = data.verdictCounts.needs_review;
  const reviewStat = needsReview > 0
    ? chalk.yellow(`${needsReview} finding${needsReview > 1 ? "s" : ""} need review`)
    : null;

  return (
    <Box flexDirection="column">
      <Text>{"  "}{topBorder}</Text>
      <Text>{"  "}{emptyLine}</Text>
      <Text>{"  "}{side}{centerPad(headline, WIDTH)}{side}</Text>
      <Text>{"  "}{emptyLine}</Text>
      <Text>{"  "}{side}{centerPad(mainStat, WIDTH)}{side}</Text>
      {chainStat && <Text>{"  "}{side}{centerPad(chainStat, WIDTH)}{side}</Text>}
      {reviewStat && <Text>{"  "}{side}{centerPad(reviewStat, WIDTH)}{side}</Text>}
      <Text>{"  "}{emptyLine}</Text>
      <Text>{"  "}{side}{centerPad(statsLine, WIDTH)}{side}</Text>
      <Text>{"  "}{emptyLine}</Text>
      <Text>{"  "}{bottomBorder}</Text>
    </Box>
  );
}

/**
 * Center text within a given width, accounting for ANSI escape codes.
 * Returns padded string (no border characters).
 */
function centerPad(text: string, width: number): string {
  // Strip ANSI to get visible length
  const visible = text.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "");
  const padding = Math.max(0, width - visible.length);
  const left = Math.floor(padding / 2);
  const right = padding - left;
  return " ".repeat(left) + text + " ".repeat(right);
}

/**
 * Interactive finding review — keyboard-driven confirm/reject for needs_review findings.
 *
 * After the pipeline completes, presents findings one at a time.
 * User presses a key to set the verdict, and it updates the DB in real-time.
 *
 *   ┌─ Review: 1/6 ──────────────────────────────────────┐
 *   │                                                      │
 *   │  ⚠ needs review (65%)  ⚠ WARNING  [codeql]          │
 *   │    src/utils/crypto.ts:15                            │
 *   │    SHA-1 used for hashing...                         │
 *   │                                                      │
 *   │  [t] true positive  [f] false positive  [s] skip     │
 *   │  [b] by design      [q] quit review                  │
 *   │                                                      │
 *   └────────────────────────────────────────────────────┘
 */

import chalk from "chalk";
import { Box, Text, useInput } from "ink";
import type React from "react";
import { useState } from "react";
import type { Verdict } from "../../types.js";
import { boxFooter, boxHeader, terminalCardWidth } from "../format.js";
import { icons } from "../icons.js";
import type { ActionableFinding } from "../state.js";
import { FindingCard } from "./FindingCard.js";

interface InteractiveReviewProps {
  findings: ActionableFinding[];
  onVerdict: (fingerprint: string, verdict: Verdict) => void;
  onQuit: () => void;
}

interface ReviewTally {
  tp: number;
  fp: number;
  by_design: number;
  skipped: number;
}

export function InteractiveReview({
  findings,
  onVerdict,
  onQuit,
}: InteractiveReviewProps): React.ReactElement {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [tally, setTally] = useState<ReviewTally>({ tp: 0, fp: 0, by_design: 0, skipped: 0 });
  const width = terminalCardWidth();

  const finding = findings[currentIndex];
  const isLast = currentIndex >= findings.length - 1;

  const advance = () => {
    if (isLast) {
      onQuit();
    } else {
      setCurrentIndex((i) => i + 1);
    }
  };

  useInput((input, key) => {
    if (!finding) return;

    if (input === "t") {
      onVerdict(finding.fingerprint, "tp");
      setTally((t) => ({ ...t, tp: t.tp + 1 }));
      advance();
    } else if (input === "f") {
      onVerdict(finding.fingerprint, "fp");
      setTally((t) => ({ ...t, fp: t.fp + 1 }));
      advance();
    } else if (input === "b") {
      onVerdict(finding.fingerprint, "by_design");
      setTally((t) => ({ ...t, by_design: t.by_design + 1 }));
      advance();
    } else if (input === "s") {
      setTally((t) => ({ ...t, skipped: t.skipped + 1 }));
      advance();
    } else if (input === "q" || key.escape) {
      onQuit();
    }
  });

  if (!finding) {
    return (
      <Box flexDirection="column">
        <Text>{""}</Text>
        <Text>
          {"  "}
          {chalk.green.bold(`${icons.success} Review complete`)}
        </Text>
        <Text>
          {"  "}
          {chalk.dim("tp:")} {tally.tp} {chalk.dim("fp:")} {tally.fp} {chalk.dim("by_design:")}{" "}
          {tally.by_design} {chalk.dim("skipped:")} {tally.skipped}
        </Text>
        <Text>{""}</Text>
      </Box>
    );
  }

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxHeader(`Review: ${currentIndex + 1}/${findings.length}`, width)}</Text>
      <Text>{""}</Text>

      <FindingCard finding={finding} />

      {/* Running tally */}
      {tally.tp + tally.fp + tally.by_design + tally.skipped > 0 && (
        <Text>
          {"  "}
          {chalk.dim("So far:")}
          {tally.tp > 0 ? ` ${chalk.red(`tp=${tally.tp}`)}` : ""}
          {tally.fp > 0 ? ` ${chalk.green(`fp=${tally.fp}`)}` : ""}
          {tally.by_design > 0 ? ` ${chalk.blue(`by_design=${tally.by_design}`)}` : ""}
          {tally.skipped > 0 ? ` ${chalk.dim(`skipped=${tally.skipped}`)}` : ""}
        </Text>
      )}
      <Text>{""}</Text>

      {/* Key bindings */}
      <Text>
        {"  "}
        {chalk.redBright.bold("[t]")} true positive {chalk.green.bold("[f]")} false positive{" "}
        {chalk.dim("[s]")} skip
      </Text>
      <Text>
        {"  "}
        {chalk.blue.bold("[b]")} by design {chalk.dim("[q]")} quit review
      </Text>

      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}

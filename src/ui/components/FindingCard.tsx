/**
 * Individual actionable finding display with rich formatting.
 *
 * Renders:
 *   ✗ TRUE POSITIVE (92%)  ✗ ERROR  [semgrep]   EXPLOITABLE
 *     src/api/users.ts:42
 *     javascript.express.security.sql-injection
 *     User input flows directly into SQL query without sanitization...
 *     ├─ Vector: HTTP POST /api/users
 *     ├─ PoC: ' OR 1=1 --
 *     └─ Taint: input → req.body.name → query() (3 hops)
 */
import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import { colorVerdict, badge, severityLabel } from "../format.js";
import { fileLink } from "../hyperlink.js";
import { renderMarkdownInline } from "../markdown.js";
import type { ActionableFinding } from "../state.js";

interface FindingCardProps {
  finding: ActionableFinding;
}

export function FindingCard({ finding }: FindingCardProps): React.ReactElement {
  const verdict = colorVerdict(finding.verdict);
  const conf = chalk.dim(`(${(finding.confidence * 100).toFixed(0)}%)`);
  const severity = severityLabel(finding.severity);
  const scanner = chalk.dim(`[${finding.taskId}]`);
  const verificationBadge = finding.verifyExploitable === 1
    ? ` ${badge("EXPLOITABLE", "red")}`
    : finding.verifyExploitable === 0
      ? ` ${badge("NOT EXPLOITABLE", "green")}`
      : "";
  const location = chalk.cyan(fileLink(finding.filePath, `${finding.filePath}:${finding.startLine}`, finding.startLine));

  // Collect detail tree items
  const details: string[] = [];

  if (finding.verifyExploitable === 1 && finding.verifyPocPayload) {
    const payload = finding.verifyPocPayload.length > 80
      ? `${finding.verifyPocPayload.slice(0, 77)}...`
      : finding.verifyPocPayload;
    details.push(`${chalk.magenta("PoC:")} ${payload}`);
  }
  if (finding.verifyAttackVector) {
    details.push(`${chalk.cyan("Vector:")} ${finding.verifyAttackVector}`);
  }
  if (finding.proofState) {
    details.push(`${chalk.magenta("Proof State:")} ${finding.proofState.replace(/_/g, " ")}`);
  }
  if (finding.engineProvenance && finding.engineProvenance.length > 0) {
    const prov = finding.engineProvenance.map((e) => `${e.kind}:${e.detail}`).join(", ");
    details.push(`${chalk.dim("Engine:")} ${prov}`);
  }
  if (finding.corroboratingSignals.length > 0) {
    const tasks = [...new Set(finding.corroboratingSignals.map((s) => s.taskId))];
    details.push(`${chalk.dim("Corroborated by:")} ${tasks.join(", ")} (+${finding.corroboratingSignals.length})`);
  }
  if (finding.pocHarnessPath) {
    details.push(`${chalk.blue("PoC Harness:")} ${fileLink(finding.pocHarnessPath)}`);
  } else if (finding.pocHarnessSkipped === 1) {
    details.push(`${chalk.yellow("PoC Harness:")} skipped (${finding.pocHarnessSkipReason ?? "no reason"})`);
  }
  if (finding.pocHarnessParsed === 0 && finding.pocHarnessParseError) {
    details.push(`${chalk.red("PoC Parse Error:")} ${finding.pocHarnessParseError}`);
  }
  if (typeof finding.pocRunVerdict === "string" && finding.pocRunVerdict) {
    const verdictColor = finding.pocRunVerdict === "PASS" ? chalk.green.bold
      : finding.pocRunVerdict === "FAIL" ? chalk.red.bold
      : finding.pocRunVerdict === "TIMEOUT" ? chalk.yellow.bold
      : chalk.red;
    const durationStr = typeof finding.pocRunDurationMs === "number"
      ? chalk.dim(` (${(finding.pocRunDurationMs / 1000).toFixed(1)}s)`)
      : "";
    details.push(`${verdictColor(`PoC Execution: ${finding.pocRunVerdict}`)}${durationStr}`);
  }

  return (
    <Box flexDirection="column">
      <Text>{"  "}{verdict} {conf}  {severity} {scanner}{verificationBadge}</Text>
      <Text>{"    "}{location}</Text>
      <Text>{"    "}{chalk.dim(finding.ruleId)}</Text>
      <Text>{"    "}{renderMarkdownInline(finding.rationale.slice(0, 120))}{finding.rationale.length > 120 ? "..." : ""}</Text>
      {details.length > 0 && details.map((detail, i) => {
        const connector = i === details.length - 1 ? icons.treeLast : icons.treeMiddle;
        return (
          <Text key={i}>{"    "}{chalk.dim(connector)} {detail}</Text>
        );
      })}
      <Text>{" "}</Text>
    </Box>
  );
}

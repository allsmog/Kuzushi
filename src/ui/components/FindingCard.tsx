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
import { CodePreview } from "./CodePreview.js";
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
  // Corroboration is handled separately as a nested tree (below)
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

  if (finding.attackPath) {
    if (finding.attackPath.chain.length > 0) {
      details.push(`${chalk.cyan("Path:")} ${finding.attackPath.chain.join(" → ")}`);
    }
    if (finding.attackPath.likelihoodReasoning) {
      details.push(`${chalk.dim("Likelihood:")} ${finding.attackPath.likelihoodReasoning}`);
    }
    if (finding.attackPath.impactReasoning) {
      details.push(`${chalk.dim("Impact:")} ${finding.attackPath.impactReasoning}`);
    }
  }

  if (finding.codeCitations && finding.codeCitations.length > 0) {
    for (const cite of finding.codeCitations.slice(0, 3)) {
      details.push(`${chalk.blue("Evidence:")} ${cite.filePath}:${cite.startLine} — ${cite.description}`);
    }
    if (finding.codeCitations.length > 3) {
      details.push(`${chalk.dim(`  ...and ${finding.codeCitations.length - 3} more citations`)}`);
    }
  }

  if (finding.assumptions && finding.assumptions.length > 0) {
    details.push(`${chalk.yellow("Assumptions:")} ${finding.assumptions.join("; ")}`);
  }

  if (finding.controls && finding.controls.length > 0) {
    const controlNames = finding.controls.map(c => c.name).join(", ");
    details.push(`${chalk.green("Controls:")} ${controlNames}`);
  }

  if (finding.blindspots && finding.blindspots.length > 0) {
    details.push(`${chalk.yellow("Blindspots:")} ${finding.blindspots.join("; ")}`);
  }

  if (finding.sourceThreatIds && finding.sourceThreatIds.length > 0) {
    details.push(`${chalk.magenta("Threats:")} ${finding.sourceThreatIds.join(", ")}`);
  }

  if (finding.blame) {
    details.push(`${chalk.dim("Introduced:")} ${finding.blame.sha} by ${finding.blame.author} on ${finding.blame.date}`);
  }

  return (
    <Box flexDirection="column">
      <Text>{"  "}{verdict} {conf}  {severity} {scanner}{verificationBadge}</Text>
      <Text>{"    "}{location}</Text>
      <CodePreview filePath={finding.filePath} line={finding.startLine} context={2} />
      <Text>{"    "}{chalk.dim(finding.ruleId)}</Text>
      <Text>{"    "}{renderMarkdownInline(finding.rationale.slice(0, 120))}{finding.rationale.length > 120 ? "..." : ""}</Text>
      {details.length > 0 && details.map((detail, i) => {
        const isLast = i === details.length - 1 && finding.corroboratingSignals.length === 0;
        const connector = isLast ? icons.treeLast : icons.treeMiddle;
        return (
          <Text key={i}>{"    "}{chalk.dim(connector)} {detail}</Text>
        );
      })}

      {/* Corroboration cluster tree */}
      {finding.corroboratingSignals.length > 0 && (
        <CorroborationTree signals={finding.corroboratingSignals} isLastDetail={true} />
      )}

      <Text>{" "}</Text>
    </Box>
  );
}

type CorroborationSignal = ActionableFinding["corroboratingSignals"][number];

function CorroborationTree({ signals, isLastDetail }: {
  signals: CorroborationSignal[];
  isLastDetail: boolean;
}): React.ReactElement {
  const uniqueTasks = [...new Set(signals.map((s) => s.taskId))];
  const connector = isLastDetail ? icons.treeLast : icons.treeMiddle;
  const continuation = isLastDetail ? " " : chalk.dim(icons.treePipe);

  return (
    <Box flexDirection="column">
      <Text>{"    "}{chalk.dim(connector)} {chalk.dim("Corroborated by")} {chalk.white(`${signals.length}`)} {chalk.dim(`scanner${signals.length > 1 ? "s" : ""}:`)} {chalk.dim(uniqueTasks.join(", "))}</Text>
      {signals.map((signal, i) => {
        const sigConnector = i === signals.length - 1 ? icons.treeLast : icons.treeMiddle;
        const cwes = signal.cwe && signal.cwe.length > 0 ? signal.cwe.join(",") : "";
        const score = signal.score != null ? chalk.dim(`score=${signal.score}`) : "";
        const loc = signal.filePath && signal.startLine
          ? chalk.cyan(fileLink(signal.filePath, `${signal.filePath}:${signal.startLine}`, signal.startLine))
          : "";
        const parts = [chalk.white(signal.taskId), cwes, score, loc].filter(Boolean);
        return (
          <Text key={i}>{"    "}{continuation}  {chalk.dim(sigConnector)} {parts.join("  ")}</Text>
        );
      })}
    </Box>
  );
}

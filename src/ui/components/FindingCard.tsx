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

import { Box, Text } from "ink";
import type React from "react";
import { badge, colorVerdict, severityLabel } from "../format.js";
import { fileLink } from "../hyperlink.js";
import { icons } from "../icons.js";
import { renderMarkdownInline } from "../markdown.js";
import { ExpandableSection } from "../primitives/ExpandableSection.js";
import type { ActionableFinding } from "../state.js";
import {
  accent,
  danger,
  dangerStrong,
  label,
  muted,
  strong,
  successStrong,
  warn,
  warnStrong,
} from "../tokens.js";
import { CodePreview } from "./CodePreview.js";

const DEBUG_ON = process.env.KUZUSHI_DEBUG === "1";

interface FindingCardProps {
  finding: ActionableFinding;
}

export function FindingCard({ finding }: FindingCardProps): React.ReactElement {
  const verdict = colorVerdict(finding.verdict);
  const conf = muted(`(${(finding.confidence * 100).toFixed(0)}%)`);
  // Prefer the triage-assessed display severity when present — it reflects
  // the human-judged impact, not the raw scanner tier.
  const severity = severityLabel(finding.displaySeverity ?? finding.severity);
  const scanner = muted(`[${finding.taskId}]`);
  const titleLine = finding.title?.trim();
  // Text fallback chain used in the summary snippet: attackNarrative if the
  // agent provided one, otherwise the terser rationale.
  const summaryText = (finding.attackNarrative ?? finding.rationale) || "";
  const verificationBadge =
    finding.verifyExploitable === 1
      ? ` ${badge("EXPLOITABLE", "red")}`
      : finding.verifyExploitable === 0
        ? ` ${badge("NOT EXPLOITABLE", "green")}`
        : "";
  const location = accent(
    fileLink(finding.filePath, `${finding.filePath}:${finding.startLine}`, finding.startLine),
  );

  // Collect detail tree items. Descriptive rows use a uniform
  // "**Key:** value" pattern (bold label, plain value) so the tree scans as
  // one visual rhythm. Rows where color carries a status signal (PoC parse
  // errors, PoC execution verdicts, skipped harnesses) keep their semantic
  // tokens so they stand out against the descriptive baseline.
  const details: string[] = [];

  if (finding.verifyExploitable === 1 && finding.verifyPocPayload) {
    const payload =
      finding.verifyPocPayload.length > 80
        ? `${finding.verifyPocPayload.slice(0, 77)}...`
        : finding.verifyPocPayload;
    details.push(`${label("PoC:")} ${payload}`);
  }
  if (finding.verifyAttackVector) {
    details.push(`${label("Vector:")} ${finding.verifyAttackVector}`);
  }
  if (finding.proofState) {
    details.push(`${label("Proof State:")} ${finding.proofState.replace(/_/g, " ")}`);
  }
  if (finding.engineProvenance && finding.engineProvenance.length > 0) {
    const prov = finding.engineProvenance.map((e) => `${e.kind}:${e.detail}`).join(", ");
    details.push(`${label("Engine:")} ${prov}`);
  }
  // Corroboration is handled separately as a nested tree (below)
  if (finding.pocHarnessPath) {
    details.push(`${label("PoC Harness:")} ${fileLink(finding.pocHarnessPath)}`);
  } else if (finding.pocHarnessSkipped === 1) {
    // Status-signaling: yellow label carries the "skipped" meaning.
    details.push(
      `${warn("PoC Harness:")} skipped (${finding.pocHarnessSkipReason ?? "no reason"})`,
    );
  }
  if (finding.pocHarnessParsed === 0 && finding.pocHarnessParseError) {
    // Status-signaling: red label for parse failure.
    details.push(`${danger("PoC Parse Error:")} ${finding.pocHarnessParseError}`);
  }
  if (typeof finding.pocRunVerdict === "string" && finding.pocRunVerdict) {
    // Status-signaling: the entire row is colored by execution verdict.
    const verdictColor =
      finding.pocRunVerdict === "PASS"
        ? successStrong
        : finding.pocRunVerdict === "FAIL"
          ? dangerStrong
          : finding.pocRunVerdict === "TIMEOUT"
            ? warnStrong
            : danger;
    const durationStr =
      typeof finding.pocRunDurationMs === "number"
        ? muted(` (${(finding.pocRunDurationMs / 1000).toFixed(1)}s)`)
        : "";
    details.push(`${verdictColor(`PoC Execution: ${finding.pocRunVerdict}`)}${durationStr}`);
  }

  if (finding.attackPath) {
    if (finding.attackPath.chain.length > 0) {
      details.push(`${label("Path:")} ${finding.attackPath.chain.join(" → ")}`);
    }
    if (finding.attackPath.likelihoodReasoning) {
      details.push(`${label("Likelihood:")} ${finding.attackPath.likelihoodReasoning}`);
    }
    if (finding.attackPath.impactReasoning) {
      details.push(`${label("Impact:")} ${finding.attackPath.impactReasoning}`);
    }
  }

  if (finding.codeCitations && finding.codeCitations.length > 0) {
    for (const cite of finding.codeCitations.slice(0, 3)) {
      details.push(
        `${label("Evidence:")} ${cite.filePath}:${cite.startLine} — ${cite.description}`,
      );
    }
    if (finding.codeCitations.length > 3) {
      details.push(`${muted(`  ...and ${finding.codeCitations.length - 3} more citations`)}`);
    }
  }

  if (finding.assumptions && finding.assumptions.length > 0) {
    details.push(`${label("Assumptions:")} ${finding.assumptions.join("; ")}`);
  }

  if (finding.controls && finding.controls.length > 0) {
    const controlNames = finding.controls.map((c) => c.name).join(", ");
    details.push(`${label("Controls:")} ${controlNames}`);
  }

  if (finding.blindspots && finding.blindspots.length > 0) {
    details.push(`${label("Blindspots:")} ${finding.blindspots.join("; ")}`);
  }

  if (finding.sourceThreatIds && finding.sourceThreatIds.length > 0) {
    details.push(`${label("Threats:")} ${finding.sourceThreatIds.join(", ")}`);
  }

  if (finding.blame) {
    details.push(
      `${label("Introduced:")} ${finding.blame.sha} by ${finding.blame.author} on ${finding.blame.date}`,
    );
  }

  const hasValidation =
    finding.verificationSteps !== undefined && finding.verificationSteps.length > 0;
  const hasDetails = details.length > 0 || finding.corroboratingSignals.length > 0 || hasValidation;

  const summary = (
    <Box flexDirection="column">
      <Text>
        {verdict} {conf} {severity} {scanner}
        {verificationBadge}
      </Text>
      {titleLine && (
        <Box paddingLeft={2}>
          <Text>{strong(titleLine)}</Text>
        </Box>
      )}
      <Box paddingLeft={2}>
        <Text>{location}</Text>
      </Box>
      <CodePreview filePath={finding.filePath} line={finding.startLine} context={2} />
      <Box paddingLeft={2}>
        <Text dimColor>{finding.ruleId}</Text>
      </Box>
      <Box paddingLeft={2}>
        <Text>
          {renderMarkdownInline(summaryText.slice(0, 160))}
          {summaryText.length > 160 ? "\u2026" : ""}
        </Text>
      </Box>
    </Box>
  );

  if (!hasDetails) {
    return (
      <Box flexDirection="column" paddingLeft={2}>
        {summary}
        <Text> </Text>
      </Box>
    );
  }

  const expandableHintCount =
    details.length + (finding.corroboratingSignals.length > 0 ? 1 : 0) + (hasValidation ? 1 : 0);

  return (
    <Box flexDirection="column" paddingLeft={2}>
      <ExpandableSection
        summary={summary}
        defaultExpanded={DEBUG_ON}
        hint={`(press space for ${expandableHintCount} detail rows)`}
      >
        {hasValidation && (
          <Box flexDirection="column">
            <Text>{label("Validation:")}</Text>
            {finding.verificationSteps!.slice(0, 4).map((step, i) => (
              <Text key={`vstep-${i}`}>
                {"  "}
                {muted(`${i + 1}.`)} {step}
              </Text>
            ))}
            {finding.verificationSteps!.length > 4 && (
              <Text>
                {"  "}
                {muted(`...and ${finding.verificationSteps!.length - 4} more`)}
              </Text>
            )}
          </Box>
        )}
        {details.map((detail, i) => {
          const isLast = i === details.length - 1 && finding.corroboratingSignals.length === 0;
          const connector = isLast ? icons.treeLast : icons.treeMiddle;
          return (
            <Text key={`detail-${i}`}>
              {muted(connector)} {detail}
            </Text>
          );
        })}
        {finding.corroboratingSignals.length > 0 && (
          <CorroborationTree signals={finding.corroboratingSignals} isLastDetail={true} />
        )}
      </ExpandableSection>
      <Text> </Text>
    </Box>
  );
}

type CorroborationSignal = ActionableFinding["corroboratingSignals"][number];

function CorroborationTree({
  signals,
  isLastDetail,
}: {
  signals: CorroborationSignal[];
  isLastDetail: boolean;
}): React.ReactElement {
  const uniqueTasks = [...new Set(signals.map((s) => s.taskId))];
  const connector = isLastDetail ? icons.treeLast : icons.treeMiddle;
  const continuation = isLastDetail ? " " : muted(icons.treePipe);

  return (
    <Box flexDirection="column">
      <Text>
        {muted(connector)} {muted("Corroborated by")} {strong(`${signals.length}`)}{" "}
        {muted(`scanner${signals.length > 1 ? "s" : ""}:`)} {muted(uniqueTasks.join(", "))}
      </Text>
      {signals.map((signal, i) => {
        const sigConnector = i === signals.length - 1 ? icons.treeLast : icons.treeMiddle;
        const cwes = signal.cwe && signal.cwe.length > 0 ? signal.cwe.join(",") : "";
        const score = signal.score != null ? muted(`score=${signal.score}`) : "";
        const loc =
          signal.filePath && signal.startLine
            ? accent(
                fileLink(
                  signal.filePath,
                  `${signal.filePath}:${signal.startLine}`,
                  signal.startLine,
                ),
              )
            : "";
        const parts = [strong(signal.taskId), cwes, score, loc].filter(Boolean);
        return (
          <Text key={i}>
            {continuation} {muted(sigConnector)} {parts.join("  ")}
          </Text>
        );
      })}
    </Box>
  );
}

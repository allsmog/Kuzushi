/**
 * ChainGroup — renders an `ExploitChain` as a bordered grouping of the
 * findings that compose it (Ink UI v2 screen 04 inner box).
 *
 * The visual model is a single rounded rectangle labeled with the chain id
 * and severity, enclosing the member findings. The caller is expected to
 * pass pre-resolved `ActionableFinding`s in step order — we don't reach back
 * into the store here so this stays a pure presentational component.
 */

import { Box, Text } from "ink";
import type React from "react";
import { severityChalk, severityStyle } from "../severity.js";
import type { ActionableFinding } from "../state.js";
import { tokens } from "../tokens.js";

export interface ChainGroupProps {
  chainId: string;
  title?: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  verified?: boolean;
  findings: ReadonlyArray<ActionableFinding>;
  /** Width of the bordered box in terminal columns. */
  width?: number;
}

export function ChainGroup({
  chainId,
  title,
  severity,
  verified,
  findings,
  width = 78,
}: ChainGroupProps): React.ReactElement {
  const bar = "\u2500".repeat(Math.max(10, width - 20));
  const sevBadge = severityBadge(severity);
  const verifiedSuffix = verified ? tokens.success(" · verified") : "";

  return (
    <Box flexDirection="column" marginTop={1}>
      <Text>
        {tokens.muted("\u250C\u2500 exploit chain · ")}
        {tokens.strong(chainId)}
        {tokens.muted(" · ")}
        {sevBadge}
        {verifiedSuffix}
        {tokens.muted(` ${bar}\u2510`)}
      </Text>
      {findings.map((f) => (
        <FindingRow key={f.fingerprint} finding={f} width={width} />
      ))}
      <Text>{tokens.muted(`\u2514${"\u2500".repeat(width)}\u2518`)}</Text>
    </Box>
  );
}

function FindingRow({
  finding,
  width,
}: {
  finding: ActionableFinding;
  width: number;
}): React.ReactElement {
  const title = finding.title ?? finding.ruleId;
  const loc = `${finding.filePath}:${finding.startLine}`;
  const verdict = finding.verdict?.toUpperCase() ?? "—";
  // Trim title so the pipe stays aligned for a ~78-col box.
  const titleClip = clip(title, Math.max(20, width - 20));
  const locClip = clip(loc, Math.max(20, width - 12));

  return (
    <Box flexDirection="column">
      <Text>
        {tokens.muted("\u2502 ")}
        {finding.displaySeverity === "critical"
          ? tokens.dangerStrong(`F-${finding.fingerprint.slice(0, 4)}`)
          : tokens.danger(`F-${finding.fingerprint.slice(0, 4)}`)}
        {"  "}
        {tokens.strong(titleClip)}
      </Text>
      <Text>
        {tokens.muted("\u2502          ")}
        {tokens.muted(locClip)}
        {tokens.muted(" · ")}
        {tokens.muted(`[${finding.taskId || "sast"}]`)}
        {tokens.muted(" · ")}
        {tokens.muted(verdict)}
      </Text>
    </Box>
  );
}

function severityBadge(severity: "CRITICAL" | "HIGH" | "MEDIUM"): string {
  const tier = severity === "CRITICAL" ? "critical" : severity === "HIGH" ? "high" : "medium";
  const style = severityStyle(tier);
  // Glyph + lowercase label — pairing guarantees tier is readable without color.
  return severityChalk(tier)(`${style.glyph} ${tier}`);
}

function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}\u2026`;
}

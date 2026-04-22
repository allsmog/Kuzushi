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
import { Table } from "../primitives/Table.js";
import type { ActionableFinding } from "../state.js";
import { SPACING, tokens } from "../tokens.js";

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
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>
        {tokens.muted("\u250C\u2500 exploit chain · ")}
        {tokens.strong(chainId)}
        {tokens.muted(" · ")}
        {sevBadge}
        {verifiedSuffix}
        {tokens.muted(` ${bar}\u2510`)}
      </Text>
      <Box paddingLeft={SPACING.md}>
        <Table
          gap={1}
          columns={[
            {
              key: "id",
              header: "ID",
              width: 8,
              render: (f: ActionableFinding) => `F-${f.fingerprint.slice(0, 4)}`,
            },
            {
              key: "title",
              header: "TITLE",
              flex: 4,
              truncate: "end",
              render: (f: ActionableFinding) => f.title ?? f.ruleId,
            },
            {
              key: "loc",
              header: "LOCATION",
              flex: 3,
              truncate: "middle",
              render: (f: ActionableFinding) => `${f.filePath}:${f.startLine}`,
            },
            {
              key: "state",
              header: "STATE",
              width: 11,
              render: (f: ActionableFinding) => f.verdict?.toUpperCase() ?? "—",
            },
          ]}
          rows={findings}
          showHeader
        />
      </Box>
      <Text>{tokens.muted(`\u2514${"\u2500".repeat(width)}\u2518`)}</Text>
    </Box>
  );
}

function severityBadge(severity: "CRITICAL" | "HIGH" | "MEDIUM"): string {
  switch (severity) {
    case "CRITICAL":
      return tokens.dangerStrong("critical");
    case "HIGH":
      return tokens.danger("high");
    default:
      return tokens.warn("medium");
  }
}

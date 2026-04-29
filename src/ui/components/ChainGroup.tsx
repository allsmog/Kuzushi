/**
 * ChainGroup — renders an `ExploitChain` as a quiet grouped table.
 */

import { Box, Text } from "ink";
import type React from "react";
import { Table } from "../primitives/Table.js";
import { severityStyle } from "../severity.js";
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
  width: _width = 78,
}: ChainGroupProps): React.ReactElement {
  const sevBadge = severityBadge(severity);
  const meta = verified ? `${sevBadge} · verified` : sevBadge;

  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Box justifyContent="space-between">
        <Text>
          {tokens.label(chainId)}
          {title ? tokens.muted(` · ${title}`) : ""}
        </Text>
        <Text>{meta}</Text>
      </Box>
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
          divider={false}
        />
      </Box>
    </Box>
  );
}

function severityBadge(severity: "CRITICAL" | "HIGH" | "MEDIUM"): string {
  const tier = severity === "CRITICAL" ? "critical" : severity === "HIGH" ? "high" : "medium";
  const style = severityStyle(tier);
  // Glyph + lowercase label — pairing guarantees tier is readable without color.
  const text = `${style.glyph} ${tier}`;
  return tier === "medium" ? tokens.warn(text) : tokens.danger(text);
}

/**
 * ChainGroup — renders an `ExploitChain` as a bordered grouping of the
 * findings that compose it (Ink UI v2 screen 04 inner box).
 *
 * The visual model is a single bordered rectangle labeled with the chain id
 * and severity, enclosing the member findings. The caller is expected to
 * pass pre-resolved `ActionableFinding`s in step order — we don't reach back
 * into the store here so this stays a pure presentational component.
 */

import { Box, Text } from "ink";
import type React from "react";
import { boxBottomLine, boxTopLine } from "../format.js";
import { Table } from "../primitives/Table.js";
import { severityChalk, severityStyle } from "../severity.js";
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
  const sevBadge = severityBadge(severity);
  const rightMeta = verified ? `${sevBadge}${tokens.success(" · verified")} ` : `${sevBadge} `;
  const chainLabel = title
    ? `${tokens.muted(" exploit chain · ")}${tokens.strong(chainId)}${tokens.muted(` · ${title} `)}`
    : `${tokens.muted(" exploit chain · ")}${tokens.strong(chainId)} `;

  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>
        {boxTopLine({
          width,
          variant: "square",
          left: `${tokens.metadata("─")}${chainLabel}`,
          right: rightMeta,
        })}
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
      <Text>{boxBottomLine({ width, variant: "square" })}</Text>
    </Box>
  );
}

function severityBadge(severity: "CRITICAL" | "HIGH" | "MEDIUM"): string {
  const tier = severity === "CRITICAL" ? "critical" : severity === "HIGH" ? "high" : "medium";
  const style = severityStyle(tier);
  // Glyph + lowercase label — pairing guarantees tier is readable without color.
  return severityChalk(tier)(`${style.glyph} ${tier}`);
}

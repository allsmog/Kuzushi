/**
 * Pre-scan config summary banner.
 *
 * Renders the resolved configuration as an aligned two-column Table so
 * labels and values land on the same column across rows regardless of
 * label length.
 */

import { Box, Text } from "ink";
import type React from "react";
import { boxFooter, boxHeader, formatCost, terminalCardWidth } from "../format.js";
import { Table } from "../primitives/Table.js";
import { SPACING } from "../tokens.js";

export interface ConfigBannerData {
  model: string;
  tasks: string[];
  severity?: string[];
  concurrency?: number;
  backend?: string;
  budget?: number;
  scanMode?: string;
}

interface ConfigBannerProps {
  config: ConfigBannerData;
}

interface Row {
  label: string;
  value: string;
}

export function ConfigBanner({ config }: ConfigBannerProps): React.ReactElement {
  const width = terminalCardWidth();
  const rows: Row[] = [
    { label: "Model", value: config.model },
    { label: "Tasks", value: config.tasks.join(", ") },
  ];
  if (config.backend && config.backend !== "claude") {
    rows.push({ label: "Backend", value: config.backend });
  }
  if (config.scanMode && config.scanMode !== "sequential") {
    rows.push({ label: "Scan mode", value: config.scanMode });
  }
  if (config.severity && config.severity.length > 0) {
    rows.push({ label: "Severity", value: config.severity.join(", ") });
  }
  if (config.concurrency && config.concurrency > 1) {
    rows.push({ label: "Concurrency", value: String(config.concurrency) });
  }
  if (config.budget != null && config.budget > 0) {
    rows.push({ label: "Budget", value: formatCost(config.budget) });
  }

  return (
    <Box flexDirection="column">
      <Text>{boxHeader("Config", width)}</Text>
      <Box paddingLeft={SPACING.md}>
        <Table<Row>
          columns={[
            { key: "label", width: 14, align: "left" },
            { key: "value", flex: 1, align: "left", truncate: "end" },
          ]}
          rows={rows}
          showHeader={false}
          divider={false}
          maxWidth={width - 2}
          gap={2}
        />
      </Box>
      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}

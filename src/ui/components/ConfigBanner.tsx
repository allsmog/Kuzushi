/**
 * Pre-scan config summary banner.
 *
 * Shows resolved configuration before the pipeline begins so the user
 * knows what settings are in effect. Rendered once via <Static>.
 *
 *   ┌─ Config ────────────────────────────────────────────┐
 *   │  Model: claude-opus       Severity: ERROR, WARNING  │
 *   │  Tasks: semgrep, codeql   Concurrency: 5            │
 *   │  Backend: pi-ai           Budget: $5.00             │
 *   └────────────────────────────────────────────────────┘
 */

import chalk from "chalk";
import { Box, Text } from "ink";
import type React from "react";
import { boxFooter, boxHeader, formatCost, terminalCardWidth } from "../format.js";

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

export function ConfigBanner({ config }: ConfigBannerProps): React.ReactElement {
  const width = terminalCardWidth();
  const rows: Array<[string, string]> = [
    ["Model", config.model],
    ["Tasks", config.tasks.join(", ")],
  ];
  if (config.backend && config.backend !== "claude") {
    rows.push(["Backend", config.backend]);
  }
  if (config.scanMode && config.scanMode !== "sequential") {
    rows.push(["Scan mode", config.scanMode]);
  }
  if (config.severity && config.severity.length > 0) {
    rows.push(["Severity", config.severity.join(", ")]);
  }
  if (config.concurrency && config.concurrency > 1) {
    rows.push(["Concurrency", String(config.concurrency)]);
  }
  if (config.budget != null && config.budget > 0) {
    rows.push(["Budget", formatCost(config.budget)]);
  }

  return (
    <Box flexDirection="column">
      <Text>{boxHeader("Config", width)}</Text>
      {rows.map(([label, value]) => (
        <Text key={label}>
          {"  "}
          {chalk.dim(`${label}:`)} {value}
        </Text>
      ))}
      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}

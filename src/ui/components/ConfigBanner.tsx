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
import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { boxHeader, boxFooter, formatCost } from "../format.js";

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
  const leftCol: Array<[string, string]> = [
    ["Model", config.model],
    ["Tasks", config.tasks.join(", ")],
  ];
  if (config.backend && config.backend !== "claude") {
    leftCol.push(["Backend", config.backend]);
  }
  if (config.scanMode && config.scanMode !== "sequential") {
    leftCol.push(["Scan mode", config.scanMode]);
  }

  const rightCol: Array<[string, string]> = [];
  if (config.severity && config.severity.length > 0) {
    rightCol.push(["Severity", config.severity.join(", ")]);
  }
  if (config.concurrency && config.concurrency > 1) {
    rightCol.push(["Concurrency", String(config.concurrency)]);
  }
  if (config.budget != null && config.budget > 0) {
    rightCol.push(["Budget", formatCost(config.budget)]);
  }

  return (
    <Box flexDirection="column">
      <Text>{boxHeader("Config", 58)}</Text>
      {leftCol.map(([label, value], i) => {
        const right = rightCol[i];
        const leftPart = `${chalk.dim(label + ":")} ${value}`;
        const rightPart = right ? `  ${chalk.dim(right[0] + ":")} ${right[1]}` : "";
        return <Text key={i}>{"  "}{leftPart}{rightPart}</Text>;
      })}
      {/* Render any remaining right-column items */}
      {rightCol.slice(leftCol.length).map(([label, value], i) => (
        <Text key={`r-${i}`}>{"  "}{" ".repeat(30)}{chalk.dim(label + ":")} {value}</Text>
      ))}
      <Text>{boxFooter(58)}</Text>
    </Box>
  );
}

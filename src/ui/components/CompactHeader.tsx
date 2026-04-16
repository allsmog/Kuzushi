import chalk from "chalk";
import { Box, Text } from "ink";
import type React from "react";
import { icons } from "../icons.js";

interface CompactHeaderProps {
  repoName: string;
  tasks: string[];
  totalFindings?: number;
  selectedForTriage?: number;
}

export function CompactHeader({
  repoName,
  tasks,
  totalFindings,
  selectedForTriage,
}: CompactHeaderProps): React.ReactElement {
  const findingsLabel =
    totalFindings != null && selectedForTriage != null
      ? `${totalFindings} found · ${selectedForTriage} selected`
      : null;

  return (
    <Box flexDirection="column" marginBottom={1}>
      <Text>
        {"  "}
        {chalk.redBright.bold("Kuzushi")} {chalk.dim("·")} {chalk.white(repoName)}
        {findingsLabel ? `${chalk.dim(" · ")}${chalk.white(findingsLabel)}` : ""}
      </Text>
      {tasks.length > 0 && (
        <Text>
          {"  "}
          {chalk.dim(icons.treeLast)} {chalk.dim(tasks.join(", "))}
        </Text>
      )}
    </Box>
  );
}

import { Box, Text } from "ink";
import type React from "react";
import { icons } from "../icons.js";
import { tokens } from "../tokens.js";

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
      ? `${totalFindings} found \u00B7 ${selectedForTriage} selected`
      : null;

  return (
    <Box flexDirection="column" marginBottom={1} paddingLeft={2}>
      <Text>
        {tokens.dangerStrong("Kuzushi")} {tokens.subtle("\u00B7")} {tokens.strong(repoName)}
        {findingsLabel ? `${tokens.subtle(" \u00B7 ")}${tokens.strong(findingsLabel)}` : ""}
      </Text>
      {tasks.length > 0 && (
        <Text>
          {tokens.muted(icons.treeLast)} {tokens.muted(tasks.join(", "))}
        </Text>
      )}
    </Box>
  );
}

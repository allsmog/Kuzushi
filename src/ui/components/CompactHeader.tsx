import { Box, Text } from "ink";
import React from "react";
import { icons } from "../icons.js";
import { SPACING, tokens } from "../tokens.js";

interface CompactHeaderProps {
  repoName: string;
  tasks: string[];
  totalFindings?: number;
  selectedForTriage?: number;
}

export const CompactHeader = React.memo(_CompactHeader);

function _CompactHeader({
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
    <Box flexDirection="column" marginBottom={SPACING.sm} paddingLeft={SPACING.md}>
      <Text>
        {tokens.metadata("Kuzushi")} {tokens.subtle("\u00B7")} {tokens.strong(repoName)}
        {findingsLabel ? `${tokens.subtle(" \u00B7 ")}${tokens.metadata(findingsLabel)}` : ""}
      </Text>
      {tasks.length > 0 && (
        <Text>
          {tokens.subtle(icons.treeLast)} {tokens.metadata(tasks.join(", "))}
        </Text>
      )}
    </Box>
  );
}

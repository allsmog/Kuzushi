/**
 * Config confirmation prompt for returning users on fresh scans.
 *
 * Shows resolved config and asks to proceed, edit, or quit. Renders the
 * resolved fields via a Table primitive so labels + values align. Keys
 * are registered with the shared keybind footer.
 */

import { Box, Text, useInput } from "ink";
import type React from "react";
import { boxFooter, boxHeader, formatCost } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { useTerminalCardWidth } from "../hooks.js";
import { Table } from "../primitives/Table.js";
import { SPACING, tokens } from "../tokens.js";

export interface ConfigConfirmData {
  model: string;
  tasks: string[];
  severity?: string[];
  concurrency?: number;
  verify?: boolean;
  pocHarness?: boolean;
  preset?: string;
  budget?: number;
}

interface ConfigConfirmProps {
  config: ConfigConfirmData;
  repoName: string;
  onProceed: () => void;
  onEdit: () => void;
  onQuit: () => void;
}

interface Row {
  label: string;
  value: string;
}

export function ConfigConfirm({
  config,
  repoName,
  onProceed,
  onEdit,
  onQuit,
}: ConfigConfirmProps): React.ReactElement {
  const width = useTerminalCardWidth();

  useRegisterKeybindings([
    { keys: "Enter", label: "Start scan" },
    { keys: "e", label: "Edit" },
    { keys: "q", label: "Quit", secondary: true },
  ]);

  useInput((input, key) => {
    if (key.return || input === "y") onProceed();
    else if (input === "e") onEdit();
    else if (input === "q" || key.escape) onQuit();
  });

  const modelShort = config.model.replace("anthropic:", "").replace("-latest", "");

  const rows: Row[] = [
    { label: "Model", value: modelShort },
    { label: "Tasks", value: config.tasks.join(", ") },
  ];
  if (config.severity && config.severity.length > 0) {
    rows.push({ label: "Severity", value: config.severity.join(", ") });
  }
  if (config.preset) rows.push({ label: "Preset", value: config.preset });
  if (config.verify) rows.push({ label: "Verify", value: "yes" });
  if (config.pocHarness) rows.push({ label: "PoC Harness", value: "yes" });
  if (config.concurrency && config.concurrency > 1) {
    rows.push({ label: "Concurrency", value: String(config.concurrency) });
  }
  if (config.budget != null && config.budget > 0) {
    rows.push({ label: "Budget", value: formatCost(config.budget) });
  }

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxHeader(`${repoName}`, width)}</Text>
      <Text>{""}</Text>
      <Box paddingLeft={SPACING.md}>
        <Text>
          {tokens.muted("Press Enter to start this scan with the resolved config below.")}
        </Text>
      </Box>
      <Text>{""}</Text>
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

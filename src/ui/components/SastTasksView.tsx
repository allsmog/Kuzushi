import { Box, Text, useStdout } from "ink";
import type React from "react";
import {
  buildSastTaskRows,
  buildSastTaskSelectionSummary,
  formatSastTaskLegend,
  formatSastTaskStateLine,
  SAST_SCAN_TOOL_NAME,
} from "../../copilot/sast-task-selection.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import type { ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { ScreenContent } from "./ScreenContent.js";

interface SastTasksViewProps {
  shell: ShellState;
}

export function SastTasksView({ shell }: SastTasksViewProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "Space", label: "toggle block" },
    { keys: "j/k", label: "move", secondary: true },
    { keys: "a", label: "mode", secondary: true },
    { keys: "o", label: "options", secondary: true },
    { keys: "r", label: "reset", secondary: true },
    { keys: "q/Esc", label: "back", secondary: true },
    { keys: "?", label: "help", secondary: true },
  ]);

  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 120;
  const compact = columns < 92;
  const options = shell.moduleOptions[SAST_SCAN_TOOL_NAME] ?? {};
  const rows = buildSastTaskRows({ options, tune: shell.tuneSnapshot });
  const summary = buildSastTaskSelectionSummary({
    options,
    tune: shell.tuneSnapshot,
    cursor: shell.sastTaskCursor,
    rows,
  });

  return (
    <ScreenContent>
      <Box flexDirection="column">
        <Text>{tokens.strong("kuzushi/sast/tasks")}</Text>
        <Box marginTop={SPACING.sm}>
          <Text>{tokens.value(formatSastTaskStateLine(summary))}</Text>
        </Box>
        <Box marginTop={SPACING.xs}>
          <Text>{tokens.muted(formatSastTaskLegend())}</Text>
        </Box>
        {rows.length > 1 ? (
          <Box marginTop={SPACING.xs}>
            <Text>
              {tokens.hint(`(${summary.activeIndex + 1} of ${rows.length})`)}
              {summary.activeIndex > 0 ? tokens.hint(" ▲") : ""}
              {summary.activeIndex < rows.length - 1 ? tokens.hint(" ▼") : ""}
            </Text>
          </Box>
        ) : null}

        <Box flexDirection="column" marginTop={SPACING.sm}>
          <Text>
            {"  "}
            {"State".padEnd(6)}
            {"Capability".padEnd(compact ? 20 : 22)}
            {"Source".padEnd(13)}
            {"Cost".padEnd(7)}
            {compact ? "" : "Notes"}
          </Text>
          <Text>
            {"  "}
            {"-----".padEnd(6)}
            {"----------------".padEnd(compact ? 20 : 22)}
            {"-----------".padEnd(13)}
            {"------".padEnd(7)}
            {compact ? "" : "-------------------------------"}
          </Text>
          {rows.map((row, index) => {
            const active = index === summary.activeIndex;
            const marker = active ? tokens.accent(">") : " ";
            const line =
              `${marker} ${row.state.padEnd(6)}` +
              `${row.label.padEnd(compact ? 20 : 22)}` +
              `${row.source.padEnd(13)}` +
              `${row.cost.padEnd(7)}` +
              (compact ? "" : row.notes);
            return <Text key={row.id}>{active ? tokens.strong(line) : line}</Text>;
          })}
        </Box>

        <Box marginTop={SPACING.sm}>
          <Text>{tokens.muted(summary.activeAction)}</Text>
        </Box>
        <Box>
          <Text>
            {tokens.muted("commands: /task toggle [id] · /task mode toggle · show options")}
          </Text>
        </Box>
      </Box>
    </ScreenContent>
  );
}

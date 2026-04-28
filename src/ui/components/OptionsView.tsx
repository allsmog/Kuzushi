/**
 * OptionsView — first-class tool option surface for the focused module.
 *
 * The shell precomputes rows from CopilotCore so this component can stay
 * presentational and renderable in tests without module-registry access.
 */

import { Box, Text } from "ink";
import type React from "react";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { Table } from "../primitives/Table.js";
import type { ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { ContextStrip } from "./ContextStrip.js";
import { ScreenContent } from "./ScreenContent.js";

interface OptionsViewProps {
  shell: ShellState;
}

export function OptionsView({ shell }: OptionsViewProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "Enter", label: "type set/show command" },
    { keys: "b", label: "back", secondary: true },
    { keys: "?", label: "help", secondary: true },
  ]);

  const view = shell.optionsView;
  const rowCount = view?.rows.length ?? 0;
  const setCount = view?.rows.filter((row) => row.isSet).length ?? 0;
  const status = view
    ? `${view.toolName} · ${rowCount} options · ${setCount} set`
    : "no tool selected";

  return (
    <ScreenContent>
      <ContextStrip status={[status]} />
      {!view ? <EmptyOptions /> : <OptionsContent view={view} />}
    </ScreenContent>
  );
}

function EmptyOptions(): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.warn("No options are loaded for this module.")}</Text>
      <Text>{tokens.muted("Run /options <tool> or return with /back.")}</Text>
    </Box>
  );
}

function OptionsContent({ view }: { view: NonNullable<ShellState["optionsView"]> }) {
  return (
    <>
      {view.taskSummary ? <TaskSummary summary={view.taskSummary} /> : null}
      <Box marginTop={SPACING.sm}>
        <Text>
          {tokens.label("Options")}
          {tokens.muted("                  * = set in this shell")}
        </Text>
      </Box>
      <Box paddingLeft={SPACING.md} marginTop={SPACING.xs}>
        <Table
          showHeader
          divider={false}
          gap={2}
          columns={[
            { key: "optionName", header: "OPTION", flex: 2, truncate: "end" },
            { key: "valueLabel", header: "VALUE", flex: 3, truncate: "middle" },
            { key: "defaultLabel", header: "DEFAULT", flex: 2, truncate: "middle" },
            { key: "description", header: "DESCRIPTION", flex: 6, truncate: "end" },
          ]}
          rows={view.rows}
          emptyMessage={`${view.toolName} has no configurable options.`}
        />
      </Box>
      <ActionsBlock />
      {view.tip ? (
        <Box marginTop={SPACING.sm}>
          <Text>{tokens.hint(view.tip)}</Text>
        </Box>
      ) : null}
    </>
  );
}

function TaskSummary({
  summary,
}: {
  summary: NonNullable<NonNullable<ShellState["optionsView"]>["taskSummary"]>;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("Effective task selection")}</Text>
      <Box paddingLeft={SPACING.md} marginTop={SPACING.xs} flexDirection="column">
        <Text>{tokens.value(summary.stateLine)}</Text>
        <Text>{tokens.muted(summary.commands)}</Text>
      </Box>
    </Box>
  );
}

function ActionsBlock(): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("actions")}</Text>
      <Box paddingLeft={SPACING.md} marginTop={SPACING.xs} flexDirection="column">
        <Text>
          {tokens.muted("set <option> <value>  ")}
          {tokens.value("set a module option")}
        </Text>
        <Text>
          {tokens.muted("show options          ")}
          {tokens.value("refresh this table")}
        </Text>
        <Text>
          {tokens.muted("show advanced         ")}
          {tokens.value("print advanced option details")}
        </Text>
        <Text>
          {tokens.muted("/back                 ")}
          {tokens.value("return to module home")}
        </Text>
      </Box>
    </Box>
  );
}

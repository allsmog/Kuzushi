/**
 * ModuleHome — the per-module landing page (D2, Ink UI v2 screen 02).
 *
 * Renders when `shell.focusedModule` is set and `shell.shellView === "module"`.
 * Four-band layout: header breadcrumb, "what it does" paragraph, tools table,
 * last-run card, and a hint footer. Everything is keyboard-driven through the
 * existing shell prompt (`scan`, `tune`, `findings`, `back`, etc.) — this
 * component is purely presentational.
 */

import { Box, Text, useStdout } from "ink";
import type React from "react";
import { icons } from "../icons.js";
import { Table } from "../primitives/Table.js";
import type { ShellModuleToolSummary, ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { ContextStrip } from "./ContextStrip.js";

interface ModuleHomeProps {
  shell: ShellState;
}

export function ModuleHome({ shell }: ModuleHomeProps): React.ReactElement {
  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 120;
  const narrow = columns < 110;
  useRegisterKeybindings([
    { keys: "Enter", label: "type tool verb" },
    { keys: "t", label: "tune", secondary: true },
    { keys: "f", label: "findings", secondary: true },
    { keys: "b", label: "back", secondary: true },
    { keys: "?", label: "help", secondary: true },
  ]);
  const moduleId = shell.focusedModule;
  if (!moduleId) {
    return <Text>{tokens.muted("(no module focused)")}</Text>;
  }

  const card = shell.moduleCatalog?.find((c) => c.id === moduleId);
  const tools: ReadonlyArray<ShellModuleToolSummary> = card?.toolSummaries ?? [];
  const panelWidth = 80;

  return (
    <Box flexDirection="column" paddingLeft={SPACING.md} marginBottom={SPACING.sm}>
      <ContextStrip
        status={card ? [card.category, `${tools.length} tools`] : [`${tools.length} tools`]}
        subtitle={card?.description}
      />
      <Box marginTop={SPACING.sm}>
        <Text>
          {tokens.strong("Primary action: ")}
          {tokens.accent("run one tool verb")}
          {tokens.muted(" (listed below).")}
        </Text>
      </Box>

      {card?.description ? (
        <Section label="what it does">
          <WrappedText text={card.description} width={74} />
        </Section>
      ) : null}

      <Section label="tools" hint="(invoke from this shell as verb, or headless via kuzushi run)">
        {tools.length === 0 ? (
          <Text>{tokens.muted("   (no tools declared)")}</Text>
        ) : (
          <Table
            showHeader
            gap={1}
            columns={[
              { key: "verb", header: "VERB", width: 14, truncate: "end" },
              { key: "description", header: "DESCRIPTION", flex: 4, truncate: "end" },
              { key: "name", header: "TOOL NAME", flex: 3, truncate: "middle" },
            ]}
            rows={tools}
          />
        )}
      </Section>

      <Section label="last run">
        <Text>
          {"   "}
          {card?.lastRunSummary
            ? tokens.value(card.lastRunSummary)
            : tokens.muted("never run for this workspace")}
        </Text>
      </Section>

    </Box>
  );
}


function Section({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>
        {tokens.label(label)}
        {hint ? tokens.muted(`   ${hint}`) : ""}
      </Text>
      <Box flexDirection="column" marginTop={SPACING.sm}>
        {children}
      </Box>
    </Box>
  );
}

function WrappedText({ text, width }: { text: string; width: number }): React.ReactElement {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let current = "";
  for (const word of words) {
    if (`${current} ${word}`.trim().length > width && current.length > 0) {
      lines.push(current);
      current = word;
    } else {
      current = current ? `${current} ${word}` : word;
    }
  }
  if (current) lines.push(current);
  let offset = 0;
  const keyedLines = lines.map((line) => {
    offset += line.length + 1;
    return { line, key: `${offset}-${line.slice(0, 16)}` };
  });

  return (
    <Box flexDirection="column">
      {keyedLines.map(({ line, key }) => (
        <Text key={key}>
          {"   "}
          {line}
        </Text>
      ))}
    </Box>
  );
}

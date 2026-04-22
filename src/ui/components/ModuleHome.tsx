/**
 * ModuleHome — the per-module landing page (D2, Ink UI v2 screen 02).
 *
 * Renders when `shell.focusedModule` is set and `shell.shellView === "module"`.
 * Four-band layout: header breadcrumb, "what it does" paragraph, tools table,
 * last-run card, and a hint footer. Everything is keyboard-driven through the
 * existing shell prompt (`scan`, `tune`, `findings`, `back`, etc.) — this
 * component is purely presentational.
 */

import { Box, Text } from "ink";
import type React from "react";
import { Table } from "../primitives/Table.js";
import type { ShellModuleCard, ShellModuleToolSummary, ShellState } from "../state.js";
import { tokens } from "../tokens.js";

interface ModuleHomeProps {
  shell: ShellState;
}

export function ModuleHome({ shell }: ModuleHomeProps): React.ReactElement {
  const moduleId = shell.focusedModule;
  if (!moduleId) {
    return <Text>{tokens.muted("(no module focused)")}</Text>;
  }

  const card = shell.moduleCatalog?.find((c) => c.id === moduleId);
  const tools: ReadonlyArray<ShellModuleToolSummary> = card?.toolSummaries ?? [];

  return (
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <Header moduleId={moduleId} card={card} />

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

      <Box marginTop={1}>
        <Text>{tokens.muted("─".repeat(78))}</Text>
      </Box>
      <Box>
        <Text>
          {tokens.hint("type a tool   ")}
          {tokens.muted("t")}
          {tokens.hint(" tune   ")}
          {tokens.muted("f")}
          {tokens.hint(" findings   ")}
          {tokens.muted("b")}
          {tokens.hint(" back   ")}
          {tokens.muted("/help")}
          {tokens.hint(" more")}
        </Text>
      </Box>
    </Box>
  );
}

function Header({
  moduleId,
  card,
}: {
  moduleId: string;
  card?: ShellModuleCard;
}): React.ReactElement {
  const tagline = card ? `· ${card.category} · ${clip(card.description, 50)}` : "";
  return (
    <Box>
      <Text>
        {tokens.muted("\u25C2 back  ")}
        {tokens.strong(moduleId)}
        {"  "}
        {tokens.muted(tagline)}
      </Text>
    </Box>
  );
}

function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}\u2026`;
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
    <Box flexDirection="column" marginTop={1}>
      <Text>
        {tokens.label(label)}
        {hint ? tokens.muted(`   ${hint}`) : ""}
      </Text>
      <Box flexDirection="column" marginTop={1}>
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

  return (
    <Box flexDirection="column">
      {lines.map((line, i) => (
        <Text key={`${i}-${line.slice(0, 10)}`}>
          {"   "}
          {line}
        </Text>
      ))}
    </Box>
  );
}

/**
 * ScreenFrame — canonical chrome for every routed Ink surface.
 *
 * It answers the trunk-test questions before the body starts:
 * where am I, what state is this screen in, what tab is active, and what
 * keys are available in the footer supplied by AppLayout.
 */
import { Box, Text, useStdout } from "ink";
import type React from "react";
import { visibleWidth } from "../format.js";
import { SPACING, tokens } from "../tokens.js";

export interface ScreenTab {
  id: string;
  label: string;
  shortcut?: string;
  active?: boolean;
}

export interface ScreenFrameProps {
  title: string;
  breadcrumbs?: ReadonlyArray<string>;
  status?: ReadonlyArray<string>;
  subtitle?: string;
  tabs?: ReadonlyArray<ScreenTab>;
  footer?: React.ReactNode;
  children: React.ReactNode;
}

export function ScreenFrame({
  title,
  breadcrumbs = [],
  status = [],
  subtitle,
  tabs,
  footer,
  children,
}: ScreenFrameProps): React.ReactElement {
  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 100;
  const compact = columns < 72;
  const clippedStatus = compact ? status.slice(0, 2) : status;

  return (
    <Box flexDirection="column" flexGrow={1} justifyContent="space-between">
      <Box flexDirection="column" flexGrow={1}>
        <Box borderStyle="single" paddingX={1} flexDirection="column">
          <Box justifyContent="space-between">
            <Text wrap="truncate-end">{tokens.strong(title)}</Text>
            {clippedStatus.length > 0 ? (
              <Text wrap="truncate-start">{tokens.muted(clippedStatus.join(" · "))}</Text>
            ) : null}
          </Box>
          {breadcrumbs.length > 0 ? (
            <Text wrap="truncate-end">{tokens.muted(breadcrumbs.join(" › "))}</Text>
          ) : null}
          {subtitle ? <Text wrap="truncate-end">{tokens.hint(subtitle)}</Text> : null}
          {tabs && tabs.length > 0 ? <TabStrip tabs={tabs} compact={compact} /> : null}
        </Box>

        <Box flexDirection="column" flexGrow={1} marginTop={SPACING.sm}>
          {children}
        </Box>
      </Box>

      {footer ? <Box marginTop={SPACING.sm}>{footer}</Box> : null}
    </Box>
  );
}

function TabStrip({
  tabs,
  compact,
}: {
  tabs: ReadonlyArray<ScreenTab>;
  compact: boolean;
}): React.ReactElement {
  const shown = compact ? tabs.slice(0, 5) : tabs;
  return (
    <Box marginTop={SPACING.xs}>
      <Text wrap="truncate-end">
        {shown
          .map((tab) => {
            const key = tab.shortcut ? `[${tab.shortcut}] ` : "";
            const label = `${key}${tab.label}`;
            const rendered = tab.active
              ? `${tokens.focus("●")} ${tokens.selection(label)}`
              : tokens.muted(label);
            return rendered;
          })
          .join(tokens.subtle("  "))}
      </Text>
    </Box>
  );
}

export function selectedRowText(text: string): string {
  return `${tokens.focus("❯")} ${tokens.selection(text)}`;
}

export function unselectedRowText(text: string): string {
  const width = visibleWidth("❯ ");
  return `${" ".repeat(width)}${text}`;
}

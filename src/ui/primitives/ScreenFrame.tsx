/**
 * ScreenFrame — canonical chrome for every routed Ink surface.
 *
 * It answers the trunk-test questions before the body starts:
 * where am I, what state is this screen in, what tab is active, and what
 * keys are available in the footer supplied by AppLayout.
 */
import { Box, Text, useStdout } from "ink";
import type React from "react";
import { truncateEnd, visibleWidth } from "../format.js";
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
  const frameLineWidth = Math.max(20, columns - 6);
  const titleLine = formatFrameLine(
    tokens.strong(title),
    clippedStatus.length > 0 ? tokens.muted(clippedStatus.join(" · ")) : "",
    frameLineWidth,
  );
  const breadcrumbLine =
    breadcrumbs.length > 0
      ? padLine(tokens.muted(breadcrumbs.join(" › ")), frameLineWidth)
      : undefined;
  const subtitleLine = subtitle ? padLine(tokens.hint(subtitle), frameLineWidth) : undefined;

  return (
    <Box flexDirection="column" flexGrow={1} flexShrink={1} justifyContent="space-between">
      <Box flexDirection="column" flexGrow={1} flexShrink={1} overflow="hidden">
        {/* flexShrink={0} so the chrome (title + breadcrumb + status + tabs)
        survives a tight outer flex layout. Without it, an ancestor with
        flexShrink={1} + overflow="hidden" can collapse the chrome rows even
        when the rendered content easily fits — the operator would see only
        the breadcrumb (or nothing), not the title + status. */}
        <Box borderStyle="single" paddingX={1} flexDirection="column" flexShrink={0}>
          <Text>{titleLine}</Text>
          {breadcrumbLine ? <Text>{breadcrumbLine}</Text> : null}
          {subtitleLine ? <Text>{subtitleLine}</Text> : null}
          {tabs && tabs.length > 0 ? <TabStrip tabs={tabs} compact={compact} /> : null}
        </Box>

        <Box
          flexDirection="column"
          flexGrow={1}
          flexShrink={1}
          overflow="hidden"
          marginTop={SPACING.sm}
        >
          {children}
        </Box>
      </Box>

      {footer ? (
        <Box marginTop={SPACING.sm} flexShrink={0}>
          {footer}
        </Box>
      ) : null}
    </Box>
  );
}

function padLine(text: string, width: number): string {
  const clipped = truncateEnd(text, width);
  return clipped + " ".repeat(Math.max(0, width - visibleWidth(clipped)));
}

function formatFrameLine(left: string, right: string, width: number): string {
  if (!right) return padLine(left, width);
  const gap = "  ";
  const leftBudget = Math.max(1, width - visibleWidth(right) - visibleWidth(gap));
  if (leftBudget <= 1) return padLine(right, width);
  const clippedLeft = truncateEnd(left, leftBudget);
  const fill = Math.max(0, width - visibleWidth(clippedLeft) - visibleWidth(right));
  return `${clippedLeft}${" ".repeat(fill)}${right}`;
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

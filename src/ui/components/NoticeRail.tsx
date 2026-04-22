/**
 * Notice rail — stack of per-event advisories (info / warning / error /
 * success) surfaced from the bus.
 *
 * Rendering has two modes:
 *   - **Expanded** (default when `expanded` is true or there are any
 *     errors): every notice renders full with icon, message, detail.
 *   - **Collapsed** (default otherwise): a single rollup line showing the
 *     per-level counts + the most recent non-error notice, plus a hint to
 *     press `n` to expand.
 *
 * Errors never roll up — an error is the kind of thing you want to see at
 * a glance. The collapsed state is purely to keep long scans from burning
 * vertical space with stale warnings.
 */

import { Box, Text } from "ink";
import React from "react";
import { icons } from "../icons.js";
import type { UINotice } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { truncateEnd } from "../format.js";

interface NoticeRailProps {
  notices: UINotice[];
  /** Toggled by the `n` keybind in App.tsx — see state.noticeRailExpanded. */
  expanded?: boolean;
}

export const NoticeRail = React.memo(_NoticeRail);

function _NoticeRail({ notices, expanded }: NoticeRailProps): React.ReactElement | null {
  if (notices.length === 0) return null;

  const errors = notices.filter((n) => n.level === "error");
  const nonErrors = notices.filter((n) => n.level !== "error");
  const showFull = expanded || errors.length > 0 || nonErrors.length <= 1;

  if (showFull) {
    return (
      <Box flexDirection="column" marginBottom={SPACING.sm} paddingLeft={SPACING.md}>
        {notices.map((notice) => (
          <Text key={notice.id}>
            {formatIcon(notice.level)} {formatMessage(notice)}
          </Text>
        ))}
      </Box>
    );
  }

  return (
    <Box flexDirection="column" marginBottom={SPACING.sm} paddingLeft={SPACING.md}>
      <Text>
        {formatRollup(notices)}
        {tokens.hint("   (n) expand")}
      </Text>
    </Box>
  );
}

function formatRollup(notices: UINotice[]): string {
  const counts = countByLevel(notices);
  const parts: string[] = [];
  if (counts.error > 0) {
    parts.push(
      tokens.danger(`${icons.error} ${counts.error} error${counts.error === 1 ? "" : "s"}`),
    );
  }
  if (counts.warning > 0) {
    parts.push(
      tokens.warn(`${icons.warning} ${counts.warning} warning${counts.warning === 1 ? "" : "s"}`),
    );
  }
  if (counts.info > 0) {
    parts.push(tokens.info(`${icons.info} ${counts.info} info`));
  }
  if (counts.success > 0) {
    parts.push(tokens.success(`${icons.success} ${counts.success} ok`));
  }
  const header = parts.join(tokens.muted("  ·  "));
  const latest = [...notices].reverse().find((n) => n.level !== "error");
  const tail = latest ? tokens.muted(`  \u2014 ${truncateEnd(latest.message, 60)}`) : "";
  return `${header}${tail}`;
}

function countByLevel(notices: UINotice[]): Record<UINotice["level"], number> {
  const counts: Record<UINotice["level"], number> = {
    info: 0,
    warning: 0,
    error: 0,
    success: 0,
  };
  for (const n of notices) counts[n.level] += 1;
  return counts;
}

function formatIcon(level: UINotice["level"]): string {
  switch (level) {
    case "success":
      return tokens.success(icons.success);
    case "warning":
      return tokens.warn(icons.warning);
    case "error":
      return tokens.danger(icons.error);
    default:
      return tokens.info(icons.info);
  }
}

function formatMessage(notice: UINotice): string {
  const message =
    notice.level === "error"
      ? tokens.danger(notice.message)
      : notice.level === "warning"
        ? tokens.warn(notice.message)
        : notice.level === "success"
          ? tokens.success(notice.message)
          : tokens.strong(notice.message);

  const detail = notice.detail ? ` ${tokens.muted(notice.detail)}` : "";
  return `${message}${detail}`;
}


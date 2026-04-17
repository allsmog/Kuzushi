import { Box, Text } from "ink";
import type React from "react";
import { icons } from "../icons.js";
import type { UINotice } from "../state.js";
import { tokens } from "../tokens.js";

interface NoticeRailProps {
  notices: UINotice[];
}

export function NoticeRail({ notices }: NoticeRailProps): React.ReactElement | null {
  if (notices.length === 0) return null;

  return (
    <Box flexDirection="column" marginBottom={1} paddingLeft={2}>
      {notices.map((notice) => (
        <Text key={notice.id}>
          {formatIcon(notice.level)} {formatMessage(notice)}
        </Text>
      ))}
    </Box>
  );
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

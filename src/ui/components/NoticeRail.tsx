import chalk from "chalk";
import { Box, Text } from "ink";
import type React from "react";
import { icons } from "../icons.js";
import type { UINotice } from "../state.js";

interface NoticeRailProps {
  notices: UINotice[];
}

export function NoticeRail({ notices }: NoticeRailProps): React.ReactElement | null {
  if (notices.length === 0) {
    return null;
  }

  return (
    <Box flexDirection="column" marginBottom={1}>
      {notices.map((notice) => (
        <Text key={notice.id}>
          {"  "}
          {formatIcon(notice.level)} {formatMessage(notice)}
        </Text>
      ))}
    </Box>
  );
}

function formatIcon(level: UINotice["level"]): string {
  switch (level) {
    case "success":
      return chalk.green(icons.success);
    case "warning":
      return chalk.yellow(icons.warning);
    case "error":
      return chalk.red(icons.error);
    default:
      return chalk.blue(icons.info);
  }
}

function formatMessage(notice: UINotice): string {
  const message =
    notice.level === "error"
      ? chalk.red(notice.message)
      : notice.level === "warning"
        ? chalk.yellow(notice.message)
        : notice.level === "success"
          ? chalk.green(notice.message)
          : chalk.white(notice.message);

  const detail = notice.detail ? ` ${chalk.dim(notice.detail)}` : "";
  return `${message}${detail}`;
}

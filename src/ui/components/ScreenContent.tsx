/**
 * ScreenContent — canonical outer wrapper for any screen-level component.
 *
 * Owns the screen's left padding and bottom margin so individual screens
 * stop reinventing `<Box flexDirection="column" paddingLeft={SPACING.md}
 * marginBottom={SPACING.sm}>`. The wrapper width / spacing is sourced from
 * the layout theme; changing it once propagates to every screen.
 *
 * Components rendered inside CopilotShell's ShellViewPanel and the App-mode
 * routing branches should both use this — AppLayout's header/footer chrome
 * sits outside, and `ScreenContent` provides the indentation that frames
 * the title visually.
 */

import { Box } from "ink";
import type React from "react";
import { useLayoutContext } from "../layout-context.js";

export interface ScreenContentProps {
  children: React.ReactNode;
}

export function ScreenContent({ children }: ScreenContentProps): React.ReactElement {
  const { theme } = useLayoutContext();
  return (
    <Box flexDirection="column" paddingLeft={theme.spacing.md} marginBottom={theme.spacing.sm}>
      {children}
    </Box>
  );
}

import { Box, Text } from "ink";
import type React from "react";
import { useLayoutContext } from "../layout-context.js";
import { tokens } from "../tokens.js";

/**
 * Canonical app shell. Header (title · status · breadcrumbs · optional subtitle)
 * comes from `useLayoutContext().navigation`. Screens render only their main
 * viewport content as `children`; chrome is owned here.
 */
export function AppLayout({
  footer,
  children,
}: {
  footer: React.ReactNode;
  children: React.ReactNode;
}): React.ReactElement {
  const { navigation, theme } = useLayoutContext();
  return (
    <Box flexDirection="column">
      <Box flexDirection="column" marginBottom={theme.spacing.sm} paddingLeft={theme.spacing.md}>
        <Text>
          {tokens.strong(navigation.title)}
          {navigation.status.length > 0
            ? tokens.subtle(`${theme.drawing.statusSeparator}${navigation.status.join(theme.drawing.statusSeparator)}`)
            : ""}
        </Text>
        {navigation.breadcrumbs.length > 0 && (
          <Text>{tokens.muted(navigation.breadcrumbs.join(theme.drawing.breadcrumbSeparator))}</Text>
        )}
        {navigation.subtitle && <Text>{tokens.hint(navigation.subtitle)}</Text>}
      </Box>
      <Box flexDirection="column">{children}</Box>
      <Box marginTop={theme.spacing.sm}>{footer}</Box>
    </Box>
  );
}

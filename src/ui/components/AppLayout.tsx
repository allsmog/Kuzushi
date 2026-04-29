import type React from "react";
import { useLayoutContext } from "../layout-context.js";
import { ScreenFrame } from "../primitives/ScreenFrame.js";

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
  const { navigation } = useLayoutContext();
  return (
    <ScreenFrame
      title={navigation.title}
      breadcrumbs={navigation.breadcrumbs}
      status={navigation.status}
      subtitle={navigation.subtitle}
      tabs={navigation.tabs}
      footer={footer}
    >
      {children}
    </ScreenFrame>
  );
}

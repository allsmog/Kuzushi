import type React from "react";
import { createContext, useContext } from "react";
import type { ShellState, UIState } from "./state.js";
import { SPACING } from "./tokens.js";

export interface NavigationMeta {
  title: string;
  breadcrumbs: string[];
  status: string[];
}

export interface LayoutTheme {
  spacing: typeof SPACING;
  selectionGlyph: string;
}

export interface LayoutContextValue {
  theme: LayoutTheme;
  navigation: NavigationMeta;
}

const STANDARD_LAYOUT_THEME: LayoutTheme = {
  spacing: SPACING,
  selectionGlyph: "❯",
};

const defaultValue: LayoutContextValue = {
  theme: STANDARD_LAYOUT_THEME,
  navigation: {
    title: "Kuzushi",
    breadcrumbs: [],
    status: [],
  },
};

const LayoutContext = createContext<LayoutContextValue>(defaultValue);

export function LayoutProvider({
  value,
  children,
}: {
  value: LayoutContextValue;
  children: React.ReactNode;
}): React.ReactElement {
  return <LayoutContext.Provider value={value}>{children}</LayoutContext.Provider>;
}

export function useLayoutContext(): LayoutContextValue {
  return useContext(LayoutContext);
}

export function deriveNavigation(
  state: Pick<UIState, "mode" | "phase" | "repoName" | "shell">,
): NavigationMeta {
  if (state.mode === "shell") {
    const shell = state.shell;
    return {
      title: shellTitle(shell),
      breadcrumbs: shellBreadcrumbs(shell),
      status: shellStatus(shell),
    };
  }

  const title =
    state.mode === "running" ? "Scan Run" : state.mode === "summary" ? "Summary" : "Preflight";
  const breadcrumbs = [state.repoName || "workspace", title];
  const status = [state.phase];
  return { title, breadcrumbs, status };
}

function shellTitle(shell: ShellState | null | undefined): string {
  if (!shell) return "Shell";
  if (shell.focusedModule) return `Module: ${shell.focusedModule}`;
  return "Module Catalog";
}

function shellBreadcrumbs(shell: ShellState | null | undefined): string[] {
  if (!shell) return ["shell"];
  const crumbs = ["shell"];
  if (shell.focusedModule) crumbs.push(shell.focusedModule);
  crumbs.push(shell.shellView ?? "catalog");
  return crumbs;
}

function shellStatus(shell: ShellState | null | undefined): string[] {
  if (!shell) return [];
  return [
    shell.processing ? "busy" : "idle",
    shell.workspace ? `workspace:${shell.workspace}` : "workspace:none",
  ];
}

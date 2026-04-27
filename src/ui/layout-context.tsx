import type React from "react";
import { createContext, useContext } from "react";
import type { ShellState, UIState } from "./state.js";
import { SPACING, WIDTHS } from "./tokens.js";

export interface NavigationMeta {
  title: string;
  breadcrumbs: string[];
  status: string[];
  /** Optional subtitle line shown beneath the title (e.g. source path). */
  subtitle?: string;
}

/** Glyph palette — every cursor, selector, and toggle shape lives here. */
export interface ThemeGlyphs {
  /** List-row selection cursor (default: ❯). */
  selection: string;
  /** Text-editor cursor block (default: █). */
  textCursor: string;
  /** Collapsed expand toggle (default: ▸). */
  expand: string;
  /** Expanded toggle (default: ▾). */
  expandOpen: string;
  /** "back" hint glyph in headers (default: ◂). */
  back: string;
}

/** Box-drawing palette — pulled by Divider, GlobalHeader, frame helpers. */
export interface ThemeDrawing {
  /** Horizontal divider rule character. */
  divider: string;
  /** Breadcrumb separator string (e.g. " / "). */
  breadcrumbSeparator: string;
  /** Inline status separator (e.g. " · "). */
  statusSeparator: string;
}

export interface LayoutTheme {
  spacing: typeof SPACING;
  widths: typeof WIDTHS;
  glyphs: ThemeGlyphs;
  drawing: ThemeDrawing;
  /**
   * @deprecated Use `glyphs.selection`. Kept for one release for any
   * out-of-tree consumers that snapshot the theme shape.
   */
  selectionGlyph: string;
}

export interface LayoutContextValue {
  theme: LayoutTheme;
  navigation: NavigationMeta;
}

export type ShellNavigationState = Pick<
  ShellState,
  "focusedModule" | "shellView" | "processing" | "workspace" | "target" | "threatTab"
>;

export const STANDARD_LAYOUT_THEME: LayoutTheme = {
  spacing: SPACING,
  widths: WIDTHS,
  glyphs: {
    selection: "❯",
    textCursor: "█",
    expand: "▸",
    expandOpen: "▾",
    back: "◂",
  },
  drawing: {
    divider: "─",
    breadcrumbSeparator: " / ",
    statusSeparator: " · ",
  },
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
  state: Pick<UIState, "mode" | "phase" | "repoName"> & {
    shell?: ShellNavigationState | null;
    /** Optional currently-running scan sub-task; used to specialise the subtitle. */
    activeScanTask?: { label: string } | null;
  },
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
  // Long-form English description of the active phase, surfaced as the
  // chrome subtitle so it renders exactly once at the top of the live area
  // (instead of inside the scrolling pipeline tree, where Ink would commit
  // it to scrollback once the tree exceeds terminal height — producing two
  // visible "now …" blocks).
  const subtitle =
    state.mode === "running"
      ? runningPhaseSubtitle(state.phase, state.activeScanTask?.label)
      : undefined;
  return subtitle ? { title, breadcrumbs, status, subtitle } : { title, breadcrumbs, status };
}

function runningPhaseSubtitle(phase: string, activeTaskLabel?: string): string | undefined {
  switch (phase) {
    case "scanning":
      return activeTaskLabel
        ? `running ${activeTaskLabel}`
        : "mapping the codebase and hunting for candidates";
    case "triaging":
      return activeTaskLabel
        ? `triaging with ${activeTaskLabel}`
        : "triaging findings with the agent";
    case "verifying":
      return activeTaskLabel ? `verifying with ${activeTaskLabel}` : "verifying exploitability";
    case "poc":
      return activeTaskLabel
        ? `building harness for ${activeTaskLabel}`
        : "generating PoC harnesses";
    default:
      return undefined;
  }
}

/** Map the current threat tab onto a human label that fits the title slot. */
const THREAT_TAB_TITLES: Record<NonNullable<ShellNavigationState["threatTab"]>, string> = {
  dfd: "data flow diagram",
  stride: "stride matrix",
  stories: "attacker stories",
  scope: "scope & criticality",
  summary: "threat summary",
};

function shellTitle(shell: ShellNavigationState | null | undefined): string {
  if (!shell) return "Shell";
  const view = shell.shellView ?? "catalog";
  if (view === "threats") return THREAT_TAB_TITLES[shell.threatTab ?? "summary"];
  if (view === "context-build") return "context build";
  if (view === "task-story") return "task details";
  if (view === "findings") return "findings";
  if (view === "finding") return "finding detail";
  if (view === "tune") return "tune";
  if (view === "options") return "options";
  if (shell.focusedModule) return `module · ${shell.focusedModule}`;
  return "module catalog";
}

function shellBreadcrumbs(shell: ShellNavigationState | null | undefined): string[] {
  if (!shell) return ["shell"];
  const crumbs = ["shell"];
  if (shell.focusedModule) crumbs.push(shell.focusedModule);
  const view = shell.shellView ?? "catalog";
  // Collapse the "module" view bread to the focused module above so we
  // don't emit "shell / sast / module" — just "shell / sast".
  if (view !== "module") crumbs.push(view);
  return crumbs;
}

function shellStatus(shell: ShellNavigationState | null | undefined): string[] {
  if (!shell) return [];
  const status: string[] = [];
  status.push(shell.processing ? "busy" : "idle");
  if (shell.workspace) status.push(`workspace:${shell.workspace}`);
  if (shell.target) status.push(`target:${compactTargetLabel(shell.target)}`);
  return status;
}

function compactTargetLabel(target: string): string {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) return target;
  const trimmed = target.replace(/\/+$/, "");
  const parts = trimmed.split("/").filter(Boolean);
  if (parts.length === 0) return target;
  const last = parts[parts.length - 1]!;
  return last.length > 0 ? last : target;
}

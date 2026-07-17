import type { ReactNode } from "react";

export const PHASES = ["map", "scan", "review", "prove", "fix"] as const;

export type Phase = (typeof PHASES)[number];

export type PhaseState = "done" | "current" | "failed" | "skipped" | "pending";

export type Outcome =
  | "idle"
  | "loading"
  | "running"
  | "success"
  | "partial"
  | "failed"
  | "canceled"
  | "interrupted"
  | "degraded"
  | "stale";

export type Tone =
  | "primary"
  | "muted"
  | "subtle"
  | "accent"
  | "success"
  | "warn"
  | "danger"
  | "map"
  | "scan"
  | "review"
  | "prove"
  | "fix";

export interface KeyHint {
  key: string;
  label: string;
}

export interface TerminalFrameProps {
  /** Neutral capture title; the real TUI itself does not draw window controls. */
  title?: string;
  /** Terminal width in character cells. */
  cols?: number;
  /** Terminal height in character rows. */
  rows?: number;
  /** Hide the neutral capture label and show only the TUI surface. */
  chromeless?: boolean;
  children: ReactNode;
}

export interface PhaseRailProps {
  current: Phase;
  statuses?: Partial<Record<Phase, PhaseState>>;
}

export interface PhasePromptProps {
  phase: Phase;
  value?: string;
  placeholder?: string;
  mode?: "prompt" | "navigate";
  notice?: string;
  hints?: readonly KeyHint[];
}

export type PlanState =
  | "planning"
  | "running"
  | "completed"
  | "partial"
  | "failed"
  | "canceled";

export interface PlanTask {
  id: string;
  label: string;
  /** Cursor row in the returned proposal. Active/inactive is represented by `skipped`. */
  selected?: boolean;
  skipped?: boolean;
  state?: "pending" | "running" | "done" | "failed" | "blocked";
  detail?: string;
}

export interface PlanningCardProps {
  goal: string;
  tasks: readonly PlanTask[];
  state?: PlanState;
  summary?: string;
  /** True when a completed planner proposal has returned for operator disposition. */
  returned?: boolean;
  controls?: readonly KeyHint[];
}

export interface SurfaceLine {
  text: ReactNode;
  tone?: Tone;
  selected?: boolean;
}

export interface Surface {
  id: string;
  title: string;
  state?: "missing" | "status" | "available" | "stale" | "blocked";
  lines: readonly SurfaceLine[];
  footer?: string;
}

export interface ResultReceipt {
  outcome: Exclude<Outcome, "idle" | "loading" | "running">;
  title: string;
  detail: string;
  recommended: string;
  controls?: readonly KeyHint[];
}

export interface PhaseCockpitProps {
  phase: Phase;
  /** Reality-derived phase, disclosed only when it differs from the selected page. */
  reality?: Phase;
  target: string;
  context?: string;
  status?: Outcome;
  next: string;
  model?: string;
  module?: string;
  cost?: string;
  rail?: PhaseRailProps["statuses"];
  result?: ResultReceipt;
  /** Contextual commands shown only when the current width and result state allow them. */
  actions?: readonly KeyHint[];
  surfaces: readonly Surface[];
  /** Visible surface id with current Navigate focus. Defaults to the first visible surface. */
  focusedSurface?: string;
  /** Conditional current/returned planning workflow, directly above the prompt. */
  plan?: PlanningCardProps;
  /** Prompt content; its phase token is always derived from `phase`. */
  prompt?: Omit<PhasePromptProps, "phase">;
  /** Current compact status/keybind footer immediately above the planning workflow. */
  footer?: {
    left: string;
    right?: string;
    controls?: readonly KeyHint[];
  };
  cols?: number;
  rows?: number;
}

export type RunState = "live" | "completed" | "partial" | "failed" | "canceled" | "interrupted";

export interface RunTask {
  id: string;
  label: string;
  state: "pending" | "running" | "done" | "failed" | "blocked" | "skipped";
  detail?: string;
}

export interface OutputLine {
  text: ReactNode;
  tone?: Tone;
  source?: string;
}

export interface RunFocusProps {
  phase?: Phase;
  runId: string;
  state: RunState;
  context: string;
  health: string;
  tasks: readonly RunTask[];
  output: readonly OutputLine[];
  currentTask?: string;
  /** Current Run Focus pane; constrained layouts preserve this operator focus. */
  focus?: "tasks" | "output";
  controls?: readonly KeyHint[];
  cols?: number;
  rows?: number;
}

export type SetupTone = "ready" | "optional" | "blocked" | "action";

export interface SetupRow {
  id: string;
  label: string;
  status: string;
  detail: string;
  tone: SetupTone;
  selected?: boolean;
}

export interface SetupFact {
  label: string;
  value: string;
}

export interface SetupAction {
  ready: boolean;
  selectedTasks: number;
  label?: string;
}

export interface SetupScreenProps {
  target: string;
  readiness: readonly SetupRow[];
  facts?: readonly SetupFact[];
  action?: SetupAction;
  cols?: number;
  rows?: number;
}

export type AttentionKind = "question" | "confirmation" | "credential" | "approval";

export interface AttentionChoice {
  key: string;
  label: string;
  detail?: string;
}

export interface AttentionCardProps {
  kind: AttentionKind;
  title: string;
  body: string;
  detail?: string;
  choices?: readonly AttentionChoice[];
  selected?: number;
  controls?: readonly KeyHint[];
}

export interface RouteRow {
  id: string;
  cells?: readonly string[];
  text?: ReactNode;
  tone?: Tone;
  detail?: string;
}

export interface RouteScreenProps {
  route: "jobs" | "replay" | "trace" | "catalog" | "help" | string;
  title: string;
  context?: string;
  rows: readonly RouteRow[];
  selected?: number;
  footer?: readonly KeyHint[];
  cols?: number;
  height?: number;
}

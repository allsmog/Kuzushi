import { formatCost } from "./format.js";

export type ShellStoryKind =
  | "phase"
  | "activity"
  | "tool"
  | "decision"
  | "artifact"
  | "finding"
  | "warning"
  | "result";

export type ShellStoryStatus = "queued" | "running" | "ok" | "fail" | "aborted" | "skipped";

export type ShellStoryImportance = "primary" | "secondary" | "debug";

export interface ShellStoryEvent {
  id: string;
  kind: ShellStoryKind;
  status: ShellStoryStatus;
  importance: ShellStoryImportance;
  message: string;
  timestamp: number;
  detail?: string;
  source?: string;
  runId?: string;
  turnId?: string;
  artifactPath?: string;
  count?: number;
  costUsd?: number;
  durable?: boolean;
}

export type ShellStoryEventDraft = Omit<ShellStoryEvent, "id" | "timestamp"> & {
  id?: string;
  timestamp?: number;
};

export interface ShellTaskStoryState {
  activeTurnId?: string;
  activeRunIds: string[];
  startedAt?: number;
  endedAt?: number;
  abortStatus?: "idle" | "aborting" | "aborted";
  abortReason?: string;
  events: ShellStoryEvent[];
}

export const SHELL_STORY_EVENT_CAP = 300;
export const SHELL_STORY_TAIL_CAP = 8;

let storySeq = 0;

export function createShellStoryEvent(
  draft: ShellStoryEventDraft,
  now: number = Date.now(),
): ShellStoryEvent {
  return {
    ...draft,
    id: draft.id ?? `story-${now}-${storySeq++}`,
    timestamp: draft.timestamp ?? now,
  };
}

export function shouldPersistStoryEvent(event: ShellStoryEvent): boolean {
  if (event.importance === "debug") return false;
  if (event.durable === true) return true;
  if (event.status === "fail" || event.status === "aborted") return true;
  return (
    event.importance === "primary" ||
    event.kind === "phase" ||
    event.kind === "decision" ||
    event.kind === "artifact" ||
    event.kind === "finding" ||
    event.kind === "warning" ||
    event.kind === "result"
  );
}

export function appendCuratedStoryEvent(
  events: ReadonlyArray<ShellStoryEvent>,
  event: ShellStoryEvent,
  cap: number = SHELL_STORY_EVENT_CAP,
): ShellStoryEvent[] {
  const last = events[events.length - 1];
  if (
    last &&
    last.kind === event.kind &&
    last.status === event.status &&
    last.message === event.message &&
    last.runId === event.runId &&
    last.turnId === event.turnId
  ) {
    return [...events.slice(0, -1), event].slice(-cap);
  }
  return [...events, event].slice(-cap);
}

export function appendStoryTail(
  tail: ReadonlyArray<ShellStoryEvent> | undefined,
  event: ShellStoryEvent,
  cap: number = SHELL_STORY_TAIL_CAP,
): ShellStoryEvent[] {
  const prev = tail ?? [];
  const newest = prev[0];
  if (
    newest &&
    newest.kind === event.kind &&
    newest.status === event.status &&
    newest.message === event.message
  ) {
    return [event, ...prev.slice(1)].slice(0, cap);
  }
  return [event, ...prev].slice(0, cap);
}

export function storyStatusLabel(status: ShellStoryStatus): string {
  if (status === "ok") return "done";
  return status;
}

export function storyKindLabel(kind: ShellStoryKind): string {
  return kind;
}

export function formatStoryEventPlain(event: ShellStoryEvent): string {
  const detail = event.detail ? ` · ${event.detail}` : "";
  const artifact = event.artifactPath ? ` · ${event.artifactPath}` : "";
  const count = event.count != null ? ` · ${event.count}` : "";
  const cost = event.costUsd != null && event.costUsd > 0 ? ` · ${formatCost(event.costUsd)}` : "";
  return `[story:${storyStatusLabel(event.status)}] ${event.message}${detail}${artifact}${count}${cost}`;
}

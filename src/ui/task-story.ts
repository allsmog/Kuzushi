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

export type ShellStoryStatus =
  | "queued"
  | "running"
  | "ok"
  | "fail"
  | "aborting"
  | "aborted"
  | "skipped";

export type ShellStoryImportance = "primary" | "secondary" | "debug";

export type ShellTaskBackgroundStatus = "running" | "completed" | "failed" | "cancelled";

export interface ShellTaskBackgroundJob {
  id: string;
  label: string;
  status: ShellTaskBackgroundStatus;
  startedAt: number;
  endedAt?: number;
}

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
  backgroundJobs?: ShellTaskBackgroundJob[];
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
  if (event.status === "fail" || event.status === "aborting" || event.status === "aborted") {
    return true;
  }
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

export function isTerminalStoryStatus(status: ShellStoryStatus): boolean {
  return status === "ok" || status === "fail" || status === "aborted" || status === "skipped";
}

export function isStoryDebugNoise(event: ShellStoryEvent): boolean {
  return event.importance === "debug" || (!shouldPersistStoryEvent(event) && !event.durable);
}

function isMechanicalStoryEvent(event: ShellStoryEvent): boolean {
  if (event.durable === true) return false;
  if (event.status !== "running") return false;
  return (
    event.importance === "debug" ||
    event.kind === "activity" ||
    (event.kind === "tool" && event.importance !== "primary")
  );
}

function sameStoryBeat(a: ShellStoryEvent, b: ShellStoryEvent): boolean {
  return (
    a.kind === b.kind &&
    a.status === b.status &&
    a.message === b.message &&
    a.source === b.source &&
    a.runId === b.runId &&
    a.turnId === b.turnId
  );
}

export function appendCuratedStoryEvent(
  events: ReadonlyArray<ShellStoryEvent>,
  event: ShellStoryEvent,
  cap: number = SHELL_STORY_EVENT_CAP,
): ShellStoryEvent[] {
  const last = events[events.length - 1];
  if (last && sameStoryBeat(last, event)) {
    return [...events.slice(0, -1), event].slice(-cap);
  }
  if (isMechanicalStoryEvent(event)) {
    const windowStart = Math.max(0, events.length - 24);
    for (let i = events.length - 1; i >= windowStart; i--) {
      const prior = events[i];
      if (!prior) continue;
      if (!isMechanicalStoryEvent(prior)) continue;
      if (!sameStoryBeat(prior, event)) continue;
      const next = events.slice();
      next[i] = event;
      return next.slice(-cap);
    }
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
  if (status === "aborting") return "interrupting";
  return status;
}

export function storyKindLabel(kind: ShellStoryKind): string {
  return kind;
}

export function createAbortStoryEvent(
  reason: string,
  status: "aborting" | "aborted",
  fields: Pick<ShellStoryEventDraft, "turnId" | "runId" | "source"> = {},
): ShellStoryEventDraft {
  return {
    kind: "result",
    status,
    importance: "primary",
    message: status === "aborting" ? "Interrupt requested" : "Interrupted by operator",
    detail: reason,
    durable: true,
    ...fields,
  };
}

export function createBackgroundJobStoryEvent(job: ShellTaskBackgroundJob): ShellStoryEventDraft {
  const status =
    job.status === "running"
      ? "running"
      : job.status === "completed"
        ? "ok"
        : job.status === "cancelled"
          ? "aborted"
          : "fail";
  const verb =
    job.status === "running"
      ? "backgrounded"
      : job.status === "completed"
        ? "completed"
        : job.status === "cancelled"
          ? "cancelled"
          : "failed";
  return {
    kind: job.status === "running" ? "decision" : "result",
    status,
    importance: job.status === "running" ? "secondary" : "primary",
    message: `${job.label} ${verb}`,
    detail: `job ${job.id}`,
    source: "jobs",
    durable: true,
  };
}

export function upsertBackgroundJob(
  jobs: ReadonlyArray<ShellTaskBackgroundJob> | undefined,
  job: ShellTaskBackgroundJob,
  cap: number = 12,
): ShellTaskBackgroundJob[] {
  const prior = jobs ?? [];
  const next = prior.filter((candidate) => candidate.id !== job.id);
  return [job, ...next].slice(0, cap);
}

export function storyTabEvents(
  events: ReadonlyArray<ShellStoryEvent>,
  tab: "live" | "artifacts" | "errors" | "debug",
): ShellStoryEvent[] {
  switch (tab) {
    case "live":
      return events.filter((event) => event.importance !== "debug");
    case "artifacts":
      return events.filter((event) => event.kind === "artifact" || Boolean(event.artifactPath));
    case "errors":
      return events.filter((event) => event.status === "fail" || event.status === "aborted");
    case "debug":
      return events.filter((event) => event.importance === "debug");
  }
}

export function formatStoryEventPlain(event: ShellStoryEvent): string {
  const detail = event.detail ? ` · ${event.detail}` : "";
  const artifact = event.artifactPath ? ` · ${event.artifactPath}` : "";
  const count = event.count != null ? ` · ${event.count}` : "";
  const cost = event.costUsd != null && event.costUsd > 0 ? ` · ${formatCost(event.costUsd)}` : "";
  return `[story:${storyStatusLabel(event.status)}] ${event.message}${detail}${artifact}${count}${cost}`;
}

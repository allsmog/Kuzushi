/**
 * Live-build runner for `/context build` — drives `gatherContextForRoot`
 * with a phase observer that streams progress into `shell.contextBuild`,
 * then writes the resulting OperatorScanContext to `.kuzushi/scan-context.json`.
 *
 * The runner is intentionally thin: observer events just mutate the store.
 * Events are funnelled through a micro-batcher that flushes at most every
 * 100 ms to keep subscribers bounded on monorepos where the grep sweep fires
 * hundreds of `grep-file-progress` events per second.
 */

import path from "node:path";
import {
  type ContextBuildEvent,
  type ContextBuildObserver,
  gatherContextForRoot,
} from "../agents/tasks/context-gatherer.js";
import {
  generateOperatorContextFromOutputs,
  loadOperatorScanContext,
  mergeOperatorContexts,
  PERSISTENT_CONTEXT_PATH,
  saveOperatorScanContext,
} from "../operator-context.js";
import type { RepoContext } from "../types.js";
import type {
  ContextBuildGrepDomainSlice,
  ContextBuildPhaseId,
  ContextBuildState,
  UIStore,
} from "../ui/state.js";
import {
  appendCuratedStoryEvent,
  appendStoryTail,
  createShellStoryEvent,
  formatStoryEventPlain,
  type ShellStoryEventDraft,
  shouldPersistStoryEvent,
} from "../ui/task-story.js";
import { toErrorMessage } from "../utils.js";

const FLUSH_INTERVAL_MS = 100;
const TAIL_BUFFER_LIMIT = 200;

/**
 * Drive a live `/context build` run. Returns a one-line summary suitable for
 * the shell's scroll-back history; throws on abort or gather errors so the
 * caller can surface the message to the operator.
 */
export async function runContextBuildLive(
  uiStore: UIStore | undefined,
  repoRoot: string,
  signal?: AbortSignal,
): Promise<string> {
  const absoluteRepoRoot = path.resolve(repoRoot);
  const scanContextPath = path.join(absoluteRepoRoot, PERSISTENT_CONTEXT_PATH);

  // Micro-batcher: keep one pending patch in flight and flush at most every
  // FLUSH_INTERVAL_MS. Events that arrive between flushes are collapsed.
  const patcher = createPatcher(uiStore);
  const observer: ContextBuildObserver = (ev) => patcher.handle(ev, absoluteRepoRoot);

  try {
    const output = await gatherContextForRoot(absoluteRepoRoot, signal, observer);
    patcher.flushSync();

    // Assemble: merge with any prior operator-reviewed context (so prior
    // accept/edit decisions carry forward) and write.
    const fresh = generateOperatorContextFromOutputs({ repoContext: output.repoContext });
    const prior = loadOperatorScanContext(absoluteRepoRoot);
    const merged = prior ? mergeOperatorContexts(prior, fresh) : fresh;
    saveOperatorScanContext(absoluteRepoRoot, merged);

    patcher.markDone(
      scanContextPath,
      output.repoContext,
      countMatches(output.fileIndex.patternMatches),
    );
    patcher.flushSync();

    return formatSummaryLine(output, scanContextPath);
  } catch (err) {
    if (signal?.aborted) {
      patcher.markAborted();
      patcher.flushSync();
      return "context:build aborted — no snapshot written.";
    }
    const message = toErrorMessage(err);
    patcher.markFailed(message);
    patcher.flushSync();
    throw err;
  }
}

// ── Event → state translation ─────────────────────────────────────────────

interface Patcher {
  handle: (ev: ContextBuildEvent, repoRoot: string) => void;
  markDone: (scanContextPath: string, repoContext: RepoContext, totalMatches: number) => void;
  markAborted: () => void;
  markFailed: (message: string) => void;
  flushSync: () => void;
}

function createPatcher(store: UIStore | undefined): Patcher {
  let pending: Partial<ContextBuildState> | null = null;
  let tailAppend: ContextBuildState["tail"] = [];
  let flushTimer: NodeJS.Timeout | null = null;

  function schedule(): void {
    if (!store) return;
    if (flushTimer) return;
    flushTimer = setTimeout(() => {
      flushTimer = null;
      flush();
    }, FLUSH_INTERVAL_MS);
  }

  function flush(): void {
    if (!store) return;
    if (!pending && tailAppend.length === 0) return;
    const patch = pending;
    const appends = tailAppend;
    pending = null;
    tailAppend = [];
    const shell = store.getState().shell;
    if (!shell) return;
    const prior = shell.contextBuild;
    if (!prior) return;
    let tail = prior.tail;
    if (appends.length > 0) {
      const combined = [...tail, ...appends];
      tail = combined.slice(Math.max(0, combined.length - TAIL_BUFFER_LIMIT));
    }
    const next: ContextBuildState = { ...prior, ...(patch ?? {}), tail };
    store.update({ shell: { ...shell, contextBuild: next } });
  }

  function mutate(f: (prev: ContextBuildState | null) => Partial<ContextBuildState> | null): void {
    if (!store) return;
    const shell = store.getState().shell;
    const prior = shell?.contextBuild ?? null;
    const delta = f(prior);
    if (!delta) return;
    pending = pending ? { ...pending, ...delta } : delta;
    schedule();
  }

  function appendTail(entry: ContextBuildState["tail"][number]): void {
    tailAppend = [...tailAppend, entry];
    schedule();
  }

  return {
    handle(ev, repoRoot) {
      mutate((prev) => applyEvent(prev, ev, repoRoot));
      const tailEntry = describeEvent(ev);
      if (tailEntry) appendTail(tailEntry);
      appendContextStory(store, ev);
    },
    markDone(scanContextPath, repoContext, totalMatches) {
      mutate((prev) => {
        if (!prev) return null;
        return {
          status: "done",
          scanContextPath,
          totalMatches,
          pillars: mergePillars(prev.pillars, repoContext),
        };
      });
      appendTail({ tsMs: Date.now(), message: `assemble  wrote ${scanContextPath}` });
      appendContextStoryDraft(store, {
        kind: "artifact",
        status: "ok",
        importance: "primary",
        message: "Context snapshot written",
        artifactPath: scanContextPath,
        count: totalMatches,
        source: "context:build",
        durable: true,
      });
      appendContextStoryDraft(store, {
        kind: "result",
        status: "ok",
        importance: "primary",
        message: "context:build done",
        detail: `${totalMatches} grep matches`,
        source: "context:build",
        durable: true,
      });
    },
    markAborted() {
      mutate((prev) => (prev ? { status: "aborted" } : null));
      appendTail({ tsMs: Date.now(), kind: "warn", message: "aborted by operator" });
      appendContextStoryDraft(store, {
        kind: "result",
        status: "aborted",
        importance: "primary",
        message: "context:build aborted",
        detail: "no snapshot written",
        source: "context:build",
        durable: true,
      });
    },
    markFailed(message) {
      mutate((prev) => (prev ? { status: "failed", errorMessage: message } : null));
      appendTail({ tsMs: Date.now(), kind: "warn", message: `failed: ${message}` });
      appendContextStoryDraft(store, {
        kind: "result",
        status: "fail",
        importance: "primary",
        message: "context:build failed",
        detail: message,
        source: "context:build",
        durable: true,
      });
    },
    flushSync() {
      if (flushTimer) {
        clearTimeout(flushTimer);
        flushTimer = null;
      }
      flush();
    },
  };
}

function appendContextStory(store: UIStore | undefined, ev: ContextBuildEvent): void {
  const draft = contextEventToStory(ev);
  if (draft) appendContextStoryDraft(store, draft);
}

function appendContextStoryDraft(store: UIStore | undefined, draft: ShellStoryEventDraft): void {
  if (!store) return;
  const shell = store.getState().shell;
  if (!shell) return;
  const runId = shell.contextBuild?.runId;
  const event = createShellStoryEvent({
    ...draft,
    ...(runId ? { runId } : {}),
    ...(shell.taskStory?.activeTurnId ? { turnId: shell.taskStory.activeTurnId } : {}),
  });
  const nextStory = {
    activeTurnId: event.turnId ?? shell.taskStory?.activeTurnId,
    activeRunIds:
      event.runId && !shell.taskStory?.activeRunIds.includes(event.runId)
        ? [...(shell.taskStory?.activeRunIds ?? []), event.runId]
        : (shell.taskStory?.activeRunIds ?? []),
    startedAt: shell.taskStory?.startedAt ?? event.timestamp,
    endedAt:
      event.kind === "result" || event.status === "fail" || event.status === "aborted"
        ? event.timestamp
        : shell.taskStory?.endedAt,
    abortStatus:
      event.status === "aborted" ? ("aborted" as const) : (shell.taskStory?.abortStatus ?? "idle"),
    abortReason:
      event.status === "aborted"
        ? (event.detail ?? shell.taskStory?.abortReason)
        : shell.taskStory?.abortReason,
    backgroundJobs: shell.taskStory?.backgroundJobs,
    events: appendCuratedStoryEvent(shell.taskStory?.events ?? [], event),
  };
  let nextShell = {
    ...shell,
    taskStory: nextStory,
    currentTool: shell.currentTool
      ? {
          ...shell.currentTool,
          storyTail: appendStoryTail(shell.currentTool.storyTail, event),
          ...(event.kind === "phase" ? { phase: event.message, subLabel: event.message } : {}),
          ...(event.runId ? { runId: event.runId } : {}),
          lastEventAt: event.timestamp,
        }
      : shell.currentTool,
  };
  if (shouldPersistStoryEvent(event)) {
    nextShell = {
      ...nextShell,
      history: [
        ...nextShell.history,
        {
          type: "story",
          text: formatStoryEventPlain(event),
          timestamp: event.timestamp,
          storyEvent: event,
          ...(event.status === "aborted" ? { abortStatus: "aborted" as const } : {}),
        },
      ],
    };
  }
  store.update({ shell: nextShell });
}

function contextEventToStory(ev: ContextBuildEvent): ShellStoryEventDraft | null {
  switch (ev.type) {
    case "phase-start":
      return {
        kind: "phase",
        status: "running",
        importance: "primary",
        message: contextPhaseLabel(ev.phase),
        source: "context:build",
        durable: true,
      };
    case "manifest-result":
      return {
        kind: "activity",
        status: ev.found ? "ok" : "skipped",
        importance: "secondary",
        message: `${ev.which} ${ev.found ? "found" : "not present"}`,
        source: "context:build",
      };
    case "walk-result":
      return {
        kind: "activity",
        status: "ok",
        importance: "secondary",
        message: "Repository walked",
        detail: `${ev.entries} entries · ${ev.sourceFiles} source files`,
        count: ev.sourceFiles,
        source: "context:build",
        durable: true,
      };
    case "path-signals-result":
      return {
        kind: "activity",
        status: "ok",
        importance: "secondary",
        message: "Path signals collected",
        detail: ev.signals.length > 0 ? ev.signals.join(" · ") : "none",
        count: ev.signals.length,
        source: "context:build",
      };
    case "grep-start":
      return {
        kind: "activity",
        status: "running",
        importance: "secondary",
        message: "Grep sweep started",
        detail: `${ev.workers} workers · ${ev.filesTotal} files · ${ev.domains.length} domains`,
        source: "context:build",
      };
    case "grep-domain-state":
      if (ev.status !== "capped") return null;
      return {
        kind: "warning",
        status: "ok",
        importance: "primary",
        message: `${ev.domain} grep cap reached`,
        detail: `${ev.matches} matches`,
        source: "context:build",
        durable: true,
      };
    case "assemble-result":
      return {
        kind: "activity",
        status: "ok",
        importance: "secondary",
        message: "Context assembled",
        detail: `${ev.sourceFileCount} source files · ${ev.patternMatchCount} matches`,
        count: ev.patternMatchCount,
        source: "context:build",
        durable: true,
      };
    default:
      return null;
  }
}

function contextPhaseLabel(phase: ContextBuildPhaseId): string {
  switch (phase) {
    case "manifests":
      return "manifest probes";
    case "walk":
      return "walk repo";
    case "path-signals":
      return "path signals";
    case "grep":
      return "grep sweep";
    case "assemble":
      return "assemble context";
    default:
      return String(phase);
  }
}

function applyEvent(
  prev: ContextBuildState | null,
  ev: ContextBuildEvent,
  _repoRoot: string,
): Partial<ContextBuildState> | null {
  if (!prev) return null;
  switch (ev.type) {
    case "phase-start": {
      const phases = {
        ...prev.phases,
        [ev.phase]: { status: "running" as const, startedAtMs: ev.atMs },
      };
      return { phases };
    }
    case "phase-done": {
      const slice = prev.phases[ev.phase];
      const phases = {
        ...prev.phases,
        [ev.phase]: {
          status: "done" as const,
          startedAtMs: slice?.startedAtMs,
          durationMs: ev.durationMs,
        },
      };
      return { phases };
    }
    case "manifest-result": {
      return {
        manifests: {
          ...prev.manifests,
          [ev.which]: ev.found ? ("found" as const) : ("miss" as const),
        },
      };
    }
    case "walk-result": {
      return {
        walk: {
          entries: ev.entries,
          dirs: ev.dirs,
          sourceFiles: ev.sourceFiles,
          cap: ev.cap,
        },
      };
    }
    case "path-signals-result": {
      return { pathSignals: ev.signals };
    }
    case "grep-start": {
      return {
        grep: {
          filesDone: 0,
          filesTotal: ev.filesTotal,
          workers: ev.workers,
          domainCap: ev.domainCap,
          domains: ev.domains.map(
            (name): ContextBuildGrepDomainSlice => ({ name, matches: 0, status: "pending" }),
          ),
        },
      };
    }
    case "grep-file-progress": {
      if (!prev.grep) return null;
      return {
        grep: {
          ...prev.grep,
          filesDone: ev.filesDone,
          filesTotal: ev.filesTotal,
        },
      };
    }
    case "grep-domain-state": {
      if (!prev.grep) return null;
      const domains = prev.grep.domains.map((d) =>
        d.name === ev.domain ? { ...d, matches: ev.matches, status: ev.status } : d,
      );
      return { grep: { ...prev.grep, domains } };
    }
    case "assemble-result": {
      return {
        pillars: mergePillars(prev.pillars, ev.repoContext),
      };
    }
    default:
      return null;
  }
}

function mergePillars(
  prev: ContextBuildState["pillars"],
  repo: RepoContext,
): ContextBuildState["pillars"] {
  return {
    architecture: {
      languages: unique(repo.languages ?? prev.architecture.languages),
      frameworks: unique(repo.frameworks ?? prev.architecture.frameworks),
      entryPoints: unique(repo.entryPoints ?? prev.architecture.entryPoints),
      ormOrDb: unique(repo.ormOrDb ?? prev.architecture.ormOrDb),
    },
    trust: {
      sanitizationLibs: unique(repo.sanitizationLibs ?? prev.trust.sanitizationLibs),
      authPatterns: unique(repo.authPatterns ?? prev.trust.authPatterns),
    },
  };
}

function describeEvent(ev: ContextBuildEvent): ContextBuildState["tail"][number] | null {
  const tsMs = Date.now();
  switch (ev.type) {
    case "phase-start":
      return { tsMs, message: `start   ${ev.phase}` };
    case "phase-done":
      return { tsMs, message: `done    ${ev.phase} (${ev.durationMs}ms)` };
    case "manifest-result":
      return {
        tsMs,
        message: `probe   ${ev.which}${ev.found ? " → found" : " → miss"}`,
      };
    case "walk-result":
      return {
        tsMs,
        message: `walk    entries=${ev.entries} dirs=${ev.dirs} sourceFiles=${ev.sourceFiles}`,
      };
    case "path-signals-result":
      return {
        tsMs,
        message: `path    ${ev.signals.length > 0 ? ev.signals.join(" · ") : "none"}`,
      };
    case "grep-start":
      return {
        tsMs,
        message: `grep    spawn ${ev.workers} workers over ${ev.filesTotal} files (${ev.domains.length} domains)`,
      };
    case "grep-domain-state":
      if (ev.status === "capped") {
        return {
          tsMs,
          kind: "warn",
          message: `grep    ${ev.domain} reached cap (${ev.matches}/cap) — stopping domain`,
        };
      }
      if (ev.status === "skipped-no-ext") {
        return { tsMs, message: `grep    ${ev.domain} skipped (no matching ext)` };
      }
      return null;
    case "assemble-result":
      return {
        tsMs,
        message: `assemble  ${ev.sourceFileCount} source files · ${ev.patternMatchCount} matches`,
      };
    default:
      return null;
  }
}

function countMatches(byDomain: Record<string, unknown[]>): number {
  return Object.values(byDomain).reduce((sum, arr) => sum + arr.length, 0);
}

function unique(arr: ReadonlyArray<string>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of arr) {
    if (!seen.has(v)) {
      seen.add(v);
      out.push(v);
    }
  }
  return out;
}

function formatSummaryLine(
  output: Awaited<ReturnType<typeof gatherContextForRoot>>,
  scanContextPath: string,
): string {
  const matchCount = Object.values(output.fileIndex.patternMatches).reduce(
    (sum, arr) => sum + arr.length,
    0,
  );
  return `context:build done — ${output.fileIndex.totalFiles} source files · ${matchCount} grep matches · wrote ${scanContextPath}`;
}

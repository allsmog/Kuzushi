import { describe, expect, it } from "vitest";
import {
  appendCuratedStoryEvent,
  appendStoryTail,
  createAbortStoryEvent,
  createBackgroundJobStoryEvent,
  createShellStoryEvent,
  formatStoryEventPlain,
  shouldPersistStoryEvent,
  storyTabEvents,
  upsertBackgroundJob,
} from "../../src/ui/task-story.js";

describe("task story curation", () => {
  it("persists durable phases, decisions, artifacts, warnings, findings, results, and failures", () => {
    const durableKinds = ["phase", "decision", "artifact", "warning", "finding", "result"] as const;
    for (const kind of durableKinds) {
      expect(
        shouldPersistStoryEvent(
          createShellStoryEvent({
            kind,
            status: "running",
            importance: "secondary",
            message: kind,
          }),
        ),
      ).toBe(true);
    }

    expect(
      shouldPersistStoryEvent(
        createShellStoryEvent({
          kind: "activity",
          status: "fail",
          importance: "secondary",
          message: "failed",
        }),
      ),
    ).toBe(true);
  });

  it("filters debug-only mechanical chatter from durable scrollback", () => {
    const event = createShellStoryEvent({
      kind: "tool",
      status: "running",
      importance: "debug",
      message: "Read · package.json",
    });

    expect(shouldPersistStoryEvent(event)).toBe(false);
  });

  it("deduplicates repeated adjacent story events by replacing the latest beat", () => {
    const first = createShellStoryEvent(
      {
        kind: "activity",
        status: "running",
        importance: "secondary",
        message: "walking files",
        runId: "run-1",
        turnId: "turn-1",
      },
      1,
    );
    const second = createShellStoryEvent(
      {
        kind: "activity",
        status: "running",
        importance: "secondary",
        message: "walking files",
        runId: "run-1",
        turnId: "turn-1",
      },
      2,
    );

    expect(appendCuratedStoryEvent([first], second)).toEqual([second]);
  });

  it("deduplicates repeated mechanical chatter inside the recent window", () => {
    const first = createShellStoryEvent(
      {
        kind: "activity",
        status: "running",
        importance: "debug",
        message: "Read · package.json",
        runId: "run-1",
      },
      1,
    );
    const spacer = createShellStoryEvent(
      {
        kind: "phase",
        status: "running",
        importance: "primary",
        message: "grep sweep",
        runId: "run-1",
      },
      2,
    );
    const second = createShellStoryEvent(
      {
        kind: "activity",
        status: "running",
        importance: "debug",
        message: "Read · package.json",
        runId: "run-1",
      },
      3,
    );

    expect(appendCuratedStoryEvent([first, spacer], second)).toEqual([second, spacer]);
  });

  it("keeps the live story tail newest-first and capped", () => {
    const events = Array.from({ length: 10 }, (_, index) =>
      createShellStoryEvent(
        {
          kind: "activity",
          status: "running",
          importance: "secondary",
          message: `step ${index}`,
        },
        index,
      ),
    );

    const tail = events.reduce((acc, event) => appendStoryTail(acc, event, 3), []);
    expect(tail.map((event) => event.message)).toEqual(["step 9", "step 8", "step 7"]);
  });

  it("formats artifacts, counts, and costs for plain output", () => {
    const event = createShellStoryEvent({
      kind: "artifact",
      status: "ok",
      importance: "primary",
      message: "Context written",
      artifactPath: ".kuzushi/scan-context.json",
      count: 12,
      costUsd: 0.02,
    });

    expect(formatStoryEventPlain(event)).toContain("[story:done] Context written");
    expect(formatStoryEventPlain(event)).toContain(".kuzushi/scan-context.json");
    expect(formatStoryEventPlain(event)).toContain("12");
  });

  it("builds durable abort events for immediate interrupt receipts", () => {
    const requested = createShellStoryEvent(createAbortStoryEvent("tool execution", "aborting"));
    const settled = createShellStoryEvent(createAbortStoryEvent("tool execution", "aborted"));

    expect(requested.message).toBe("Interrupt requested");
    expect(settled.message).toBe("Interrupted by operator");
    expect(shouldPersistStoryEvent(requested)).toBe(true);
    expect(shouldPersistStoryEvent(settled)).toBe(true);
  });

  it("tracks background jobs and formats background story beats", () => {
    const running = { id: "1", label: "threat-hunt:run", status: "running" as const, startedAt: 1 };
    const done = { ...running, status: "completed" as const, endedAt: 2 };

    expect(upsertBackgroundJob([running], done)).toEqual([done]);
    const event = createShellStoryEvent(createBackgroundJobStoryEvent(done));
    expect(event.message).toBe("threat-hunt:run completed");
    expect(event.detail).toBe("job 1");
  });

  it("filters task-story tabs", () => {
    const events = [
      createShellStoryEvent({
        kind: "artifact",
        status: "ok",
        importance: "primary",
        message: "a",
      }),
      createShellStoryEvent({
        kind: "result",
        status: "fail",
        importance: "primary",
        message: "f",
      }),
      createShellStoryEvent({
        kind: "activity",
        status: "running",
        importance: "debug",
        message: "d",
      }),
    ];

    expect(storyTabEvents(events, "artifacts").map((event) => event.message)).toEqual(["a"]);
    expect(storyTabEvents(events, "errors").map((event) => event.message)).toEqual(["f"]);
    expect(storyTabEvents(events, "debug").map((event) => event.message)).toEqual(["d"]);
  });
});

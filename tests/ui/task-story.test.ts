import { describe, expect, it } from "vitest";
import {
  appendCuratedStoryEvent,
  appendStoryTail,
  createShellStoryEvent,
  formatStoryEventPlain,
  shouldPersistStoryEvent,
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
});

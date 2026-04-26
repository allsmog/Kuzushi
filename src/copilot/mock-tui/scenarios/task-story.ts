import { baseShell, mockShellModuleCards } from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "task-story",
  description: "Turn narrative — durable story beats with phase + decision rows.",
  seed: () => {
    const cards = mockShellModuleCards();
    const now = Date.now();
    return {
      shell: baseShell({
        shellView: "task-story",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        target: process.cwd(),
        taskStory: {
          activeTurnId: "turn-1",
          activeRunIds: ["run-1"],
          startedAt: now - 22_000,
          abortStatus: "idle",
          events: [
            {
              id: "story-1",
              kind: "phase",
              status: "ok",
              importance: "primary",
              message: "Building context",
              timestamp: now - 21_000,
              durable: true,
            },
            {
              id: "story-2",
              kind: "tool",
              status: "ok",
              importance: "primary",
              message: "Scan · sast",
              detail: "4 findings",
              timestamp: now - 14_000,
              costUsd: 0.31,
              durable: true,
            },
            {
              id: "story-3",
              kind: "decision",
              status: "ok",
              importance: "primary",
              message: "Triaged 4 findings",
              detail: "2 critical confirmed, 1 high, 1 dismissed",
              timestamp: now - 8_000,
              durable: true,
            },
            {
              id: "story-4",
              kind: "result",
              status: "ok",
              importance: "primary",
              message: "Run complete",
              detail: "$0.42 · 22s",
              timestamp: now - 1_000,
              costUsd: 0.42,
              durable: true,
            },
          ],
        },
      }),
    };
  },
});

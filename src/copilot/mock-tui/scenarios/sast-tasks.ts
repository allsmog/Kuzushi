import { baseShell, mockShellModuleCards } from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "sast-tasks",
  description: "SAST task selector — mode, blocked rows, and task actions.",
  seed: () => {
    const cards = mockShellModuleCards();
    return {
      shell: baseShell({
        shellView: "sast-tasks",
        focusedModule: "sast",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        target: process.cwd(),
        sastTaskCursor: 1,
        tuneSnapshot: {
          preset: "standard",
          tasks: ["semgrep"],
          verify: false,
          autoPatch: false,
          triageConcurrency: 3,
          model: "anthropic:claude-sonnet-4-6",
        },
        moduleOptions: {
          "sast:scan": {
            disabledTasks: ["codeql"],
          },
        },
      }),
    };
  },
});

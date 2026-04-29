import { baseShell, mockModuleRun, mockShellModuleCards } from "../../../ui/mock-fixtures.js";
import type { AgentActivityLine, ModuleRunStep } from "../../../ui/state.js";
import { registerScenario } from "../index.js";

/**
 * Live module-run scenario. Static seed renders a `running` slice with
 * three steps and a small evidence tail. `playback` pushes new evidence
 * lines on a timer and flips the run to `done` after ~6s.
 *
 * Used to visually verify streaming evidence + step-glyph transitions in
 * `ModuleRunView` without a real `carlini-threat-hunt` run.
 */
registerScenario({
  id: "module-run-active",
  description: "Live module run — running with streaming evidence (use --playback).",
  seed: () => {
    const cards = mockShellModuleCards();
    return {
      shell: baseShell({
        shellView: "module-run",
        focusedModule: "carlini-threat-hunt",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        moduleRun: mockModuleRun({
          moduleId: "carlini-threat-hunt",
          status: "running",
          startedSecondsAgo: 4,
          evidenceLines: 3,
        }),
        target: process.cwd(),
      }),
    };
  },
  playback: (store) => {
    const stream: Array<Omit<AgentActivityLine, "index" | "total">> = [
      { kind: "tool-start", toolName: "Grep", detail: '"jwt.verify\\("' },
      { kind: "tool-complete", toolName: "Grep", detail: "2 matches" },
      { kind: "reasoning", detail: "checking signing key rotation policy" },
      { kind: "tool-start", toolName: "Read", detail: "src/auth/jwt.ts" },
      { kind: "tool-complete", toolName: "Read", detail: "210 lines" },
      { kind: "finding-preview", detail: "Audience claim not validated on /admin" },
      { kind: "summary", detail: "actor concluded — 1 finding" },
    ];

    const timers: NodeJS.Timeout[] = [];
    let counter = 5;
    let i = 0;

    const pushNext = (): void => {
      if (i >= stream.length) {
        // Mark steps complete + flip run status.
        const finalSteps: ReadonlyArray<ModuleRunStep> = [
          { id: "boot", title: "load threat model", status: "done", elapsedSeconds: 1 },
          {
            id: "spawn",
            title: "spawn actor agents",
            status: "done",
            count: "4/4 actors",
          },
          { id: "merge", title: "merge findings", status: "done", count: "1 path" },
        ];
        store.setModuleRunSteps(finalSteps);
        store.patchModuleRun({ status: "done", costUsd: 0.74 });
        return;
      }
      const sample = stream[i++];
      counter += 1;
      store.pushModuleRunActivity({ ...sample, index: counter, total: counter });
      timers.push(setTimeout(pushNext, 800));
    };

    timers.push(setTimeout(pushNext, 600));

    return () => {
      for (const timer of timers) clearTimeout(timer);
    };
  },
});

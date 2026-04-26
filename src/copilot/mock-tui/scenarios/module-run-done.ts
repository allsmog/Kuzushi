import {
  baseShell,
  baseSummary,
  makeActionableFindings,
  mockModuleRun,
  mockShellModuleCards,
} from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "module-run-done",
  description: "ModuleRunView — completed run with findings + artifacts.",
  seed: () => {
    const cards = mockShellModuleCards();
    const findings = makeActionableFindings(8, 11);
    return {
      phase: "summary",
      summary: baseSummary(findings),
      shell: baseShell({
        shellView: "module-run",
        focusedModule: "threat-hunt",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        moduleRun: mockModuleRun({
          moduleId: "threat-hunt",
          status: "done",
          startedSecondsAgo: 124,
          evidenceLines: 8,
        }),
        target: process.cwd(),
      }),
    };
  },
});

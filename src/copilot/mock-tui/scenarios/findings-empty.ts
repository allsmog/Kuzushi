import { baseShell, baseSummary, mockShellModuleCards } from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "findings-empty",
  description: "Findings view with zero findings post-scan — empty-state copy.",
  seed: () => {
    const cards = mockShellModuleCards();
    return {
      phase: "summary",
      summary: baseSummary([]),
      shell: baseShell({
        shellView: "findings",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        target: process.cwd(),
      }),
    };
  },
});

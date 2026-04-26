import { baseShell, mockShellModuleCards, mockThreatModel } from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "threats-dfd",
  description: "Threat model — DFD tab with elements grouped by trust zone.",
  seed: () => {
    const cards = mockShellModuleCards();
    return {
      shell: baseShell({
        shellView: "threats",
        threatTab: "dfd",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        threatModel: mockThreatModel(),
        target: process.cwd(),
      }),
    };
  },
});

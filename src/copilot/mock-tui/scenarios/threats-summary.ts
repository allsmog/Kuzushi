import { baseShell, mockShellModuleCards, mockThreatModel } from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "threats-summary",
  description: "Threat model — count bar charts + drives + artifact paths.",
  seed: () => {
    const cards = mockShellModuleCards();
    return {
      shell: baseShell({
        shellView: "threats",
        threatTab: "summary",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        threatModel: mockThreatModel(),
        target: process.cwd(),
      }),
    };
  },
});

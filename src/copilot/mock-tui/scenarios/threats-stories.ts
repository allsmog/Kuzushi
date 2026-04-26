import { baseShell, mockShellModuleCards, mockThreatModel } from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "threats-stories",
  description: "Threat model — attacker-story narrative cards.",
  seed: () => {
    const cards = mockShellModuleCards();
    return {
      shell: baseShell({
        shellView: "threats",
        threatTab: "stories",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        threatModel: mockThreatModel(),
        target: process.cwd(),
      }),
    };
  },
});

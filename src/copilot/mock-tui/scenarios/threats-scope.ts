import { baseShell, mockShellModuleCards, mockThreatModel } from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "threats-scope",
  description: "Threat model — criticality calibration + out-of-scope + operator edits.",
  seed: () => {
    const cards = mockShellModuleCards();
    return {
      shell: baseShell({
        shellView: "threats",
        threatTab: "scope",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        threatModel: mockThreatModel(),
        target: process.cwd(),
      }),
    };
  },
});

import {
  baseShell,
  baseSummary,
  makeActionableFindings,
  mockShellModuleCards,
} from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "finding",
  description: "Single finding deep page — F-0001 open from a 5-finding spread.",
  seed: () => {
    const cards = mockShellModuleCards();
    const findings = makeActionableFindings(5, 7);
    return {
      phase: "summary",
      summary: baseSummary(findings),
      shell: baseShell({
        shellView: "finding",
        openFindingId: "F-0001",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        target: process.cwd(),
      }),
    };
  },
});

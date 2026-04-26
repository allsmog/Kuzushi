import {
  baseShell,
  baseSummary,
  makeActionableFindings,
  mockShellModuleCards,
} from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "findings-many",
  description: "50 mixed-severity findings — exercises pagination + severity glyphs.",
  seed: () => {
    const cards = mockShellModuleCards();
    const findings = makeActionableFindings(50, 42);
    return {
      phase: "summary",
      summary: baseSummary(findings),
      shell: baseShell({
        shellView: "findings",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        target: process.cwd(),
      }),
    };
  },
});

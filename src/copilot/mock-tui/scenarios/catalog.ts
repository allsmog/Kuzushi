import {
  baseShell,
  mockShellHistoryEntries,
  mockShellModuleCards,
} from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "catalog",
  description: "Module catalog grouped by category — entry view for the shell.",
  seed: () => {
    const cards = mockShellModuleCards();
    return {
      shell: baseShell({
        shellView: "catalog",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        history: mockShellHistoryEntries(),
        target: process.cwd(),
      }),
    };
  },
});

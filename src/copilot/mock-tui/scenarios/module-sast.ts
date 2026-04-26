import { baseShell, mockShellModuleCards } from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "module-sast",
  description: "ModuleHome focused on the SAST module — tools table + last-run.",
  seed: () => {
    const cards = mockShellModuleCards();
    return {
      shell: baseShell({
        shellView: "module",
        focusedModule: "sast",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        target: process.cwd(),
      }),
    };
  },
});

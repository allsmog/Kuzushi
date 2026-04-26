import { baseShell, mockShellModuleCards, mockTuneSnapshot } from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "tune",
  description: "Tune view for the SAST module — six controls + house-rules block.",
  seed: () => {
    const cards = mockShellModuleCards();
    return {
      shell: baseShell({
        shellView: "tune",
        focusedModule: "sast",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        tuneSnapshot: mockTuneSnapshot("sast"),
        target: process.cwd(),
      }),
    };
  },
});

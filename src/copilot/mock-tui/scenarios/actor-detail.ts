import { baseShell, mockAgentActivity, mockShellModuleCards } from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "actor-detail",
  description: "Per-actor transcript drill-in (Tool / result / Thinking / Finding rows).",
  seed: () => {
    const cards = mockShellModuleCards();
    const fingerprint = "threat-hunt:Authenticated_User:0";
    return {
      shell: baseShell({
        shellView: "actor-detail",
        focusedModule: "threat-hunt",
        focusedActor: fingerprint,
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        target: process.cwd(),
      }),
      agentActivity: mockAgentActivity({ fingerprint, count: 6 }),
    };
  },
});

import { baseShell, mockPromptsEditor, mockShellModuleCards } from "../../../ui/mock-fixtures.js";
import { registerScenario } from "../index.js";

registerScenario({
  id: "prompts-editor",
  description: "Per-module prompts table — one default verb + one file-overridden verb.",
  seed: () => {
    const cards = mockShellModuleCards();
    return {
      shell: baseShell({
        shellView: "prompts-editor",
        focusedModule: "carlini-threat-hunt",
        modules: cards.map((c) => c.id),
        moduleCatalog: cards,
        promptsEditor: mockPromptsEditor("carlini-threat-hunt"),
        target: process.cwd(),
      }),
    };
  },
});

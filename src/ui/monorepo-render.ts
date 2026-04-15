/**
 * Ink renderer for monorepo module progress.
 *
 * Creates a live-updating tree view of module execution during Phase 2.
 * Falls back to console.log for non-TTY.
 */
import type { MonorepoModuleState } from "./components/MonorepoProgress.js";

export interface MonorepoUIHandle {
  updateModule(path: string, update: Partial<MonorepoModuleState>): void;
  cleanup(): void;
}

/**
 * Create and mount the monorepo progress renderer.
 *
 * @param modules - Initial list of modules to display
 * @param phaseLabel - Label for the phase header
 * @returns Handle for updating module state and cleaning up
 */
export async function createMonorepoRenderer(
  modules: Array<{ name: string; path: string; tasks?: string[] }>,
  phaseLabel?: string,
): Promise<MonorepoUIHandle> {
  const moduleStates: MonorepoModuleState[] = modules.map((m) => ({
    name: m.name,
    path: m.path,
    status: "pending",
    tasks: m.tasks,
  }));

  if (!process.stdout.isTTY) {
    // Non-TTY: simple console.log fallback
    return {
      updateModule(path, update) {
        const mod = moduleStates.find((m) => m.path === path);
        if (!mod) return;
        Object.assign(mod, update);

        if (update.status === "complete") {
          const verdicts = mod.tp != null ? `tp=${mod.tp} fp=${mod.fp ?? 0} nr=${mod.needsReview ?? 0}` : "";
          console.log(`  ◆ ${mod.name}  ${verdicts}`);
        } else if (update.status === "error") {
          console.log(`  ✗ ${mod.name}  ${update.detail ?? "error"}`);
        } else if (update.status === "scanning" || update.status === "triaging") {
          const activity = update.activityDetail ? `  ${update.activityDetail}` : "";
          console.log(`  ● ${mod.name}  ${update.detail ?? update.status}...${activity}`);
        }
      },
      cleanup() {},
    };
  }

  // TTY: use Ink for live progress
  const { render } = await import("ink");
  const { createElement } = await import("react");
  const { MonorepoProgress } = await import("./components/MonorepoProgress.js");

  // Simple reactive state for the Ink component
  let currentModules = [...moduleStates];
  let rerender: (() => void) | undefined;

  function MonorepoApp() {
    const { useState, useEffect } = require("react") as typeof import("react");
    const [modules, setModules] = useState(currentModules);

    useEffect(() => {
      rerender = () => setModules([...currentModules]);
      return () => { rerender = undefined; };
    }, []);

    return createElement(MonorepoProgress, { modules, phaseLabel });
  }

  const instance = render(createElement(MonorepoApp));

  return {
    updateModule(path, update) {
      const mod = currentModules.find((m) => m.path === path);
      if (!mod) return;
      Object.assign(mod, update);
      currentModules = [...currentModules];
      rerender?.();
    },
    cleanup() {
      instance.unmount();
    },
  };
}

/**
 * UI renderer entry point.
 *
 * Creates a UIStore and either renders an Ink app (TTY) or registers
 * a plain-text fallback (non-TTY/piped output).
 */
import { createUIStore, type UIStore } from "./state.js";

export interface UIRenderer {
  store: UIStore;
  cleanup: () => void;
}

/**
 * Create and mount the UI renderer.
 *
 * When stdout is a TTY, renders the full Ink app with live updates.
 * Otherwise, falls back to plain console.log output with enhanced formatting.
 */
export async function createUIRenderer(): Promise<UIRenderer> {
  const store = createUIStore();

  if (process.stdout.isTTY) {
    // Dynamic import to avoid loading React/Ink when not needed (CI, pipes)
    const { render } = await import("ink");
    const { App } = await import("./App.js");
    const { createElement } = await import("react");
    const instance = render(createElement(App, { store }));
    return {
      store,
      cleanup: () => instance.unmount(),
    };
  }

  // Non-TTY fallback — use plain-text renderer
  const { registerPlainTextRenderer } = await import("./plain-renderer.js");
  const unsubscribe = registerPlainTextRenderer(store);
  return {
    store,
    cleanup: unsubscribe,
  };
}

/**
 * UI renderer entry point.
 *
 * Creates a UIStore and either renders an Ink app (TTY) or registers
 * a plain-text fallback (non-TTY/piped output).
 *
 * Registers an `exit` handler that writes the ANSI "cursor show" sequence
 * unconditionally so a crash, Ctrl+C during a modal, or an SDK abort never
 * leaves a hidden cursor in the user's shell. This is redundant with
 * `useCursorVisibility` at the component level but acts as a process-wide
 * safety net.
 */
import { createUIStore, type UIStore } from "./state.js";

export interface UIRenderer {
  store: UIStore;
  cleanup: () => void;
}

export interface CreateUIRendererOptions {
  /**
   * CI mode — skip Ink entirely and attach the machine-readable stream
   * formatter (`src/ui/ci-stream.ts`) instead. Useful for `--ci` / build
   * pipelines where we want one line per stage transition rather than a
   * live TUI.
   */
  ci?: boolean;
}

const SHOW_CURSOR = "\u001b[?25h";

let exitHandlerInstalled = false;

function ensureExitCursorRestore(): void {
  if (exitHandlerInstalled) return;
  exitHandlerInstalled = true;
  const restore = () => {
    if (!process.stdout.isTTY) return;
    try {
      process.stdout.write(SHOW_CURSOR);
    } catch {
      /* noop */
    }
  };
  process.once("exit", restore);
  process.once("SIGINT", () => {
    restore();
  });
  process.once("SIGTERM", () => {
    restore();
  });
}

/**
 * Create and mount the UI renderer.
 *
 * When stdout is a TTY, renders the full Ink app with live updates.
 * Otherwise, falls back to plain console.log output with enhanced formatting.
 */
export async function createUIRenderer(options: CreateUIRendererOptions = {}): Promise<UIRenderer> {
  const store = createUIStore();
  ensureExitCursorRestore();

  // CI mode — skip Ink, attach the stream formatter. Runs ahead of the TTY
  // check so `--ci` is honoured even from an interactive terminal (handy
  // for `kuzushi scan ... --ci | tee run.log`).
  if (options.ci) {
    const { attachCiStream } = await import("./ci-stream.js");
    const unsubscribe = attachCiStream(store);
    return { store, cleanup: unsubscribe };
  }

  if (process.stdout.isTTY) {
    // Detect terminal theme before rendering so colors adapt
    const { detectTheme } = await import("./theme.js");
    await detectTheme(200).catch(() => {}); // best-effort, don't block

    // Dynamic import to avoid loading React/Ink when not needed (CI, pipes)
    const { render } = await import("ink");
    const { App } = await import("./App.js");
    const { createElement } = await import("react");
    const instance = render(createElement(App, { store }));
    return {
      store,
      cleanup: () => {
        instance.unmount();
        // Ensure cursor is visible after unmount even if Ink's default
        // restore ran before our exit handler installs.
        if (process.stdout.isTTY) {
          try {
            process.stdout.write(SHOW_CURSOR);
          } catch {
            /* noop */
          }
        }
      },
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

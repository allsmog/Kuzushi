/**
 * REPL command handler — bridges slash commands to pipeline actions.
 *
 * Commands modify the UIStore state and/or publish bus events
 * to control the running pipeline.
 */

import type { CommandResult, ReplCommand } from "./components/CommandInput.js";
import type { UIStore } from "./state.js";

export interface ReplContext {
  store: UIStore;
  /** Fingerprints to skip (accumulated via /skip). */
  skippedFingerprints: Set<string>;
  /** Rules to suppress (accumulated via /skip-rule). */
  suppressedRules: Set<string>;
  /** Path focus filter. */
  focusPath: string | null;
  /** Whether triage is paused. */
  paused: boolean;
}

export function createReplContext(store: UIStore): ReplContext {
  const ctx: ReplContext = {
    store,
    skippedFingerprints: new Set(),
    suppressedRules: new Set(),
    focusPath: null,
    paused: false,
  };
  // Expose REPL state on the store so the orchestrator can read it
  syncReplState(ctx);
  return ctx;
}

function syncReplState(ctx: ReplContext): void {
  ctx.store.update({
    replState: {
      skippedFingerprints: ctx.skippedFingerprints,
      suppressedRules: ctx.suppressedRules,
      focusPath: ctx.focusPath,
      paused: ctx.paused,
    },
  });
}

export function handleReplCommand(ctx: ReplContext, cmd: ReplCommand): CommandResult {
  switch (cmd.name) {
    case "skip": {
      if (cmd.args.length === 0) {
        return { message: "Usage: /skip <fingerprint>", type: "error" };
      }
      const fp = cmd.args[0]!;
      ctx.skippedFingerprints.add(fp);
      syncReplState(ctx);
      return { message: `Skipping finding ${fp.slice(0, 12)}...`, type: "success" };
    }

    case "skip-rule": {
      if (cmd.args.length === 0) {
        return { message: "Usage: /skip-rule <ruleId>", type: "error" };
      }
      const rule = cmd.args[0]!;
      ctx.suppressedRules.add(rule);
      syncReplState(ctx);
      return { message: `Suppressing rule: ${rule}`, type: "success" };
    }

    case "focus": {
      if (cmd.args.length === 0) {
        if (ctx.focusPath) {
          ctx.focusPath = null;
          syncReplState(ctx);
          return { message: "Focus cleared", type: "success" };
        }
        return { message: "Usage: /focus <path> (or /focus to clear)", type: "error" };
      }
      ctx.focusPath = cmd.args[0]!;
      syncReplState(ctx);
      return { message: `Focusing on: ${ctx.focusPath}`, type: "success" };
    }

    case "pause": {
      ctx.paused = true;
      syncReplState(ctx);
      return { message: "Pausing after current finding...", type: "success" };
    }

    case "resume": {
      ctx.paused = false;
      syncReplState(ctx);
      return { message: "Resuming triage", type: "success" };
    }

    case "status": {
      const state = ctx.store.getState();
      const phase = state.phase;
      const progress = state.progress;
      const cost = state.runningCostUsd;
      const skipped = ctx.skippedFingerprints.size;
      const suppressed = ctx.suppressedRules.size;

      const parts: string[] = [
        `Phase: ${phase}`,
        `Progress: ${progress.current}/${progress.total}`,
        `Cost: $${cost.toFixed(2)}`,
      ];
      if (skipped > 0) parts.push(`Skipped: ${skipped}`);
      if (suppressed > 0) parts.push(`Suppressed rules: ${suppressed}`);
      if (ctx.focusPath) parts.push(`Focus: ${ctx.focusPath}`);
      if (ctx.paused) parts.push("PAUSED");

      return { message: parts.join(" │ "), type: "info" };
    }

    case "cost": {
      const state = ctx.store.getState();
      const cost = state.runningCostUsd;
      return { message: `Running cost: $${cost.toFixed(2)}`, type: "info" };
    }

    default:
      return { message: `Unknown command: /${cmd.name}`, type: "error" };
  }
}

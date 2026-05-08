/**
 * InteractiveSessionDispatcher — pushes onto the driver stack when
 * `sessions -I <ref>` resolves a live session. Every input line routes
 * to `SessionHandle.interact()`; `exit` / `background` / `back` pops
 * the dispatcher.
 *
 * Distinct from `sessions -i <ref> <input>` (one-shot) which stays on
 * the base dispatcher and returns a single response. The -I variant
 * parks the operator "inside" the session for an extended conversation.
 */

import type { SessionHandle } from "../../sessions/manager.js";
import { toErrorMessage } from "../../utils.js";
import type { CommandContext, CommandDispatcher, CommandResult } from "./types.js";

const COMMANDS: Record<string, string> = {
  exit: "Leave the session REPL and return to the shell",
  background: "Alias for exit — leave the REPL without closing the session",
  back: "Alias for exit",
  help: "Show REPL usage",
  // Every other line goes to the session. The fallback is handled in execute().
};

export class InteractiveSessionDispatcher implements CommandDispatcher {
  readonly name: string;
  readonly commands = COMMANDS;

  constructor(
    private readonly handle: SessionHandle,
    private readonly sessionId: string,
  ) {
    const labelBase = handle.record.alias ?? sessionId.slice(0, 8);
    this.name = `session(${labelBase})`;
  }

  async execute(
    cmd: string,
    _args: string[],
    _ctx: CommandContext,
  ): Promise<CommandResult | undefined> {
    if (cmd === "exit" || cmd === "background" || cmd === "back") {
      return { pop: true, output: `[*] Left session ${this.sessionId.slice(0, 8)}.` };
    }
    if (cmd === "help") {
      return {
        output: [
          `Interactive session REPL — session ${this.sessionId.slice(0, 8)}`,
          "  exit / background / back — return to shell (session stays open)",
          "  anything else — sent to the session",
        ].join("\n"),
      };
    }
    // Fall through — the Driver will call `fallback()` for anything not in
    // our commands map.
    return undefined;
  }

  async fallback(line: string, ctx: CommandContext): Promise<CommandResult> {
    if (!this.handle.interact) {
      return { output: "[-] Session does not support interact()." };
    }
    try {
      const out = await this.handle.interact(line, ctx.signal);
      return { output: out };
    } catch (err) {
      return {
        output: `[-] session: ${toErrorMessage(err)}`,
      };
    }
  }
}

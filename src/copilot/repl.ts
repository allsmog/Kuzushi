/**
 * Dev escape hatch — Node REPL with framework objects pre-bound.
 *
 * Inspired by msfconsole's `irb`: when you need to poke at live state
 * (registry, bus, workspace, jobs), you don't want to restart the shell
 * and re-establish scan context. Drop into a REPL, inspect, exit.
 *
 * The REPL shares stdin/stdout with the host process, so Ink / readline
 * should be paused before calling this. Resolves when the REPL session
 * ends (either `.exit`, Ctrl+D, or an explicit `process.exit` in the
 * REPL context — we use REPLServer#close to normalize all of them).
 */

import repl from "node:repl";

export interface OpenReplOptions {
  /** Prompt prefix. Defaults to `kuzushi> `. */
  prompt?: string;
  /** Context bindings exposed to the REPL. */
  context: Record<string, unknown>;
  /** Optional greeting printed before the first prompt. */
  greeting?: string;
}

/**
 * Start an interactive Node REPL with the given context. Returns a Promise
 * that resolves when the REPL closes. Never rejects — any error inside the
 * REPL is printed to its own output stream.
 */
export function openRepl(opts: OpenReplOptions): Promise<void> {
  const greeting =
    opts.greeting ??
    [
      "[*] Entering Kuzushi dev REPL.",
      "    Bound globals:",
      `    ${Object.keys(opts.context).sort().join(", ")}`,
      "    Type .exit or ^D to return to the shell.",
    ].join("\n");
  process.stdout.write(`${greeting}\n`);

  return new Promise<void>((resolve) => {
    const server = repl.start({
      prompt: opts.prompt ?? "kuzushi> ",
      useColors: true,
      useGlobal: false,
    });
    // Bind each entry as a non-enumerable context property so `tab` completion
    // and direct references both work inside the REPL.
    for (const [key, value] of Object.entries(opts.context)) {
      Object.defineProperty(server.context, key, {
        configurable: false,
        enumerable: true,
        value,
      });
    }
    server.on("exit", () => resolve());
  });
}

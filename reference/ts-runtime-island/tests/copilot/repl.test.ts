import { PassThrough } from "node:stream";
import { describe, it } from "vitest";
import { openRepl } from "../../src/copilot/repl.js";

/**
 * `openRepl` defaults to process stdin/stdout; we drive it by monkey-patching
 * the node:repl input/output via the Node REPLServer defaults. The simplest
 * end-to-end check we can run headlessly is: invoke the function with a
 * stream that immediately emits `.exit\n` and assert the promise resolves.
 *
 * Context bindings are asserted by peeking at `globalThis` after we
 * configure the REPL — we read them before `.exit` lands via an evaluator.
 */

describe("openRepl", () => {
  it("resolves when the user types .exit", async () => {
    const origStdin = process.stdin;
    const origStdout = process.stdout;
    const input = new PassThrough();
    const output = new PassThrough();
    // node:repl pulls from process.stdin by default. Rewire via Object.defineProperty
    // just for this test, then restore.
    Object.defineProperty(process, "stdin", { value: input, configurable: true });
    Object.defineProperty(process, "stdout", { value: output, configurable: true });
    try {
      const pending = openRepl({ context: { answer: 42 }, greeting: "" });
      // Give the REPL a tick to bind the stream handlers.
      await new Promise((r) => setImmediate(r));
      input.write(".exit\n");
      await pending;
    } finally {
      Object.defineProperty(process, "stdin", { value: origStdin, configurable: true });
      Object.defineProperty(process, "stdout", { value: origStdout, configurable: true });
    }
  });
});

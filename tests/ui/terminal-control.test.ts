import { describe, expect, it } from "vitest";
import {
  ENTER_ALTERNATE_SCREEN,
  EXIT_ALTERNATE_SCREEN,
  enterAlternateScreen,
  SHOW_CURSOR,
} from "../../src/ui/terminal-control.js";

class FakeStdout {
  isTTY = true;
  writes: string[] = [];

  write(chunk: string): boolean {
    this.writes.push(chunk);
    return true;
  }
}

describe("terminal alternate screen control", () => {
  it("enters and exits the alternate screen exactly once", () => {
    const stdout = new FakeStdout();
    const cleanup = enterAlternateScreen({
      stdout,
      processLike: process,
    });

    expect(stdout.writes).toEqual([ENTER_ALTERNATE_SCREEN]);

    cleanup();
    cleanup();

    expect(stdout.writes).toEqual([ENTER_ALTERNATE_SCREEN, EXIT_ALTERNATE_SCREEN, SHOW_CURSOR]);
  });

  it("reference-counts nested sessions", () => {
    const stdout = new FakeStdout();
    const first = enterAlternateScreen({ stdout, processLike: process });
    const second = enterAlternateScreen({ stdout, processLike: process });

    expect(stdout.writes).toEqual([ENTER_ALTERNATE_SCREEN]);

    first();
    expect(stdout.writes).toEqual([ENTER_ALTERNATE_SCREEN]);

    second();
    expect(stdout.writes).toEqual([ENTER_ALTERNATE_SCREEN, EXIT_ALTERNATE_SCREEN, SHOW_CURSOR]);
  });

  it("skips non-TTY output", () => {
    const stdout = new FakeStdout();
    stdout.isTTY = false;

    const cleanup = enterAlternateScreen({ stdout, processLike: process });
    cleanup();

    expect(stdout.writes).toEqual([]);
  });
});

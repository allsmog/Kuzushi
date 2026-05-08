/**
 * Tool loop detection for agentic triage/verification.
 *
 * Detects 4 patterns of stuck behavior:
 * 1. Exact repeat: same tool + same args called N times consecutively
 * 2. Ping-pong: alternating between 2 tool calls
 * 3. Expanding loop: same tool with monotonically increasing args
 * 4. No-progress: tool calls returning identical results
 */

import { createHash } from "node:crypto";

/** Detected loop pattern. */
export interface LoopDetection {
  pattern: "exact-repeat" | "ping-pong" | "expanding-loop" | "no-progress";
  tool: string;
  count: number;
}

interface CallRecord {
  tool: string;
  argsHash: string;
  resultHash: string;
  args: Record<string, unknown>;
}

const WINDOW_SIZE = 20;
const EXACT_REPEAT_THRESHOLD = 3;
const PING_PONG_THRESHOLD = 4; // 4 cycles = 8 calls
const NO_PROGRESS_THRESHOLD = 3;

function hashObj(obj: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(obj ?? ""))
    .digest("hex")
    .slice(0, 16);
}

export class LoopDetector {
  private readonly window: CallRecord[] = [];

  /**
   * Record a tool call and check for loop patterns.
   * Returns a LoopDetection if a pattern is detected, null otherwise.
   */
  recordCall(
    tool: string,
    args: Record<string, unknown>,
    resultHash: string,
  ): LoopDetection | null {
    const argsHash = hashObj(args);
    this.window.push({ tool, argsHash, resultHash, args });

    if (this.window.length > WINDOW_SIZE) {
      this.window.shift();
    }

    return (
      this.detectExactRepeat() ??
      this.detectPingPong() ??
      this.detectExpandingLoop() ??
      this.detectNoProgress()
    );
  }

  /** Reset the detection window. */
  reset(): void {
    this.window.length = 0;
  }

  private detectExactRepeat(): LoopDetection | null {
    const len = this.window.length;
    if (len < EXACT_REPEAT_THRESHOLD) return null;

    const last = this.window[len - 1];
    let count = 1;

    for (let i = len - 2; i >= 0; i--) {
      const prev = this.window[i];
      if (prev.tool === last.tool && prev.argsHash === last.argsHash) {
        count++;
      } else {
        break;
      }
    }

    if (count >= EXACT_REPEAT_THRESHOLD) {
      return { pattern: "exact-repeat", tool: last.tool, count };
    }
    return null;
  }

  private detectPingPong(): LoopDetection | null {
    const len = this.window.length;
    const minCalls = PING_PONG_THRESHOLD * 2;
    if (len < minCalls) return null;

    const a = this.window[len - 2];
    const b = this.window[len - 1];

    if (a.tool === b.tool && a.argsHash === b.argsHash) return null;

    let cycles = 0;
    for (let i = len - 1; i >= 1; i -= 2) {
      const cur = this.window[i];
      const prev = this.window[i - 1];
      if (
        cur.tool === b.tool &&
        cur.argsHash === b.argsHash &&
        prev.tool === a.tool &&
        prev.argsHash === a.argsHash
      ) {
        cycles++;
      } else {
        break;
      }
    }

    if (cycles >= PING_PONG_THRESHOLD) {
      return { pattern: "ping-pong", tool: `${a.tool} <-> ${b.tool}`, count: cycles };
    }
    return null;
  }

  private detectExpandingLoop(): LoopDetection | null {
    const len = this.window.length;
    if (len < EXACT_REPEAT_THRESHOLD) return null;

    const last = this.window[len - 1];
    const sameToolCalls = [];
    for (let i = len - 1; i >= 0; i--) {
      if (this.window[i].tool === last.tool) {
        sameToolCalls.unshift(this.window[i]);
      } else {
        break;
      }
    }

    if (sameToolCalls.length < EXACT_REPEAT_THRESHOLD) return null;

    // Check for a numeric arg that's monotonically increasing
    const numericKeys = this.findNumericArgs(sameToolCalls);
    for (const key of numericKeys) {
      const values = sameToolCalls.map((c) => {
        const val = c.args[key];
        return typeof val === "number" ? val : NaN;
      });

      if (values.every((v) => !Number.isNaN(v))) {
        let increasing = true;
        for (let i = 1; i < values.length; i++) {
          if (values[i] <= values[i - 1]) {
            increasing = false;
            break;
          }
        }
        if (increasing) {
          return {
            pattern: "expanding-loop",
            tool: last.tool,
            count: sameToolCalls.length,
          };
        }
      }
    }

    return null;
  }

  private detectNoProgress(): LoopDetection | null {
    const len = this.window.length;
    if (len < NO_PROGRESS_THRESHOLD) return null;

    const last = this.window[len - 1];
    let count = 1;

    for (let i = len - 2; i >= 0; i--) {
      const prev = this.window[i];
      if (prev.tool === last.tool && prev.resultHash === last.resultHash) {
        count++;
      } else {
        break;
      }
    }

    if (count >= NO_PROGRESS_THRESHOLD) {
      return { pattern: "no-progress", tool: last.tool, count };
    }
    return null;
  }

  private findNumericArgs(calls: CallRecord[]): string[] {
    if (calls.length === 0) return [];
    const firstArgs = calls[0].args;
    return Object.keys(firstArgs).filter((k) => typeof firstArgs[k] === "number");
  }
}

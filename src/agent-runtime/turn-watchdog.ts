/**
 * Turn watchdog: detects stuck agent sessions that stop yielding.
 *
 * If no message is yielded within the configured timeout, the watchdog
 * fires and aborts the current LLM call via AbortController.
 */

const DEFAULT_TIMEOUT_MS = 120_000; // 2 minutes

export class TurnWatchdog {
  private timer: ReturnType<typeof setTimeout> | null = null;
  private readonly timeoutMs: number;
  private readonly abortController: AbortController;
  private fired = false;

  constructor(abortController: AbortController, timeoutMs: number = DEFAULT_TIMEOUT_MS) {
    this.abortController = abortController;
    this.timeoutMs = timeoutMs;
  }

  /** Start or reset the watchdog timer. Call this on every yield. */
  kick(): void {
    if (this.fired) return;

    if (this.timer !== null) {
      clearTimeout(this.timer);
    }

    this.timer = setTimeout(() => {
      this.fired = true;
      this.abortController.abort(new Error("Turn watchdog timeout"));
    }, this.timeoutMs);
  }

  /** Check if the watchdog has fired. */
  hasFired(): boolean {
    return this.fired;
  }

  /** Stop the watchdog. Call when the query completes normally. */
  stop(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}

/**
 * CLI error shapes and centralized exit-code semantics.
 *
 * Exit codes:
 *   0  — clean
 *   1  — generic failure (e.g. findings present in scan, tool error)
 *   2  — usage / config / auth error (wrong flags, missing env, invalid config)
 *   3  — unexpected crash (stack trace printed to stderr under KUZUSHI_DEBUG)
 *
 * These constants are the single source of truth. Subcommands should raise a
 * CliUsageError/CliConfigError (→ exit 2) or let unexpected errors bubble
 * up (→ exit 3). Domain-specific "expected failure" paths (scan found TPs,
 * patch didn't reach SOUND) exit with 1.
 */

export const EXIT_CODES = {
  OK: 0,
  FAILURE: 1,
  USAGE: 2,
  CRASH: 3,
} as const;

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES];

export interface CliCommandErrorOptions {
  exitCode?: number;
  details?: string[];
}

export class CliCommandError extends Error {
  readonly exitCode: number;
  readonly details: string[];

  constructor(message: string, options: CliCommandErrorOptions = {}) {
    super(message);
    this.name = new.target.name;
    this.exitCode = options.exitCode ?? EXIT_CODES.FAILURE;
    this.details = [...(options.details ?? [])];
  }
}

/** Usage / flag / argument errors. Exit code 2. */
export class CliUsageError extends CliCommandError {
  constructor(message: string, options: CliCommandErrorOptions = {}) {
    super(message, { exitCode: EXIT_CODES.USAGE, ...options });
  }
}

/** Config / credential / environment errors. Exit code 2. */
export class CliConfigError extends CliCommandError {
  constructor(message: string, options: CliCommandErrorOptions = {}) {
    super(message, { exitCode: EXIT_CODES.USAGE, ...options });
  }
}

export function wrapCliAction<Args extends unknown[]>(
  handler: (...args: Args) => Promise<void> | void,
): (...args: Args) => Promise<void> {
  return async (...args: Args) => {
    try {
      await handler(...args);
    } catch (error) {
      if (error instanceof CliCommandError) {
        console.error(formatCliErrorMessage(error.message));
        for (const detail of error.details) {
          console.error(detail);
        }
        if (isDebugMode() && error.stack) {
          console.error("");
          console.error(error.stack);
        }
        process.exit(error.exitCode);
      }
      const message = error instanceof Error ? error.message : String(error);
      console.error(formatCliErrorMessage(message));
      if (error instanceof Error && isDebugMode() && error.stack) {
        console.error("");
        console.error(error.stack);
      } else if (!isDebugMode()) {
        console.error("Run with --debug or KUZUSHI_DEBUG=1 for a full stack trace.");
      }
      process.exit(EXIT_CODES.CRASH);
    }
  };
}

function formatCliErrorMessage(message: string): string {
  return message.startsWith("Error: ") ? message : `Error: ${message}`;
}

function isDebugMode(): boolean {
  return process.env.KUZUSHI_DEBUG === "1";
}

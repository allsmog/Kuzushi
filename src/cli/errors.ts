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
    this.exitCode = options.exitCode ?? 1;
    this.details = [...(options.details ?? [])];
  }
}

export class CliUsageError extends CliCommandError {}

export class CliConfigError extends CliCommandError {}

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
        process.exit(error.exitCode);
      }
      const message = error instanceof Error ? error.message : String(error);
      console.error(formatCliErrorMessage(message));
      process.exit(1);
    }
  };
}

function formatCliErrorMessage(message: string): string {
  return message.startsWith("Error: ") ? message : `Error: ${message}`;
}

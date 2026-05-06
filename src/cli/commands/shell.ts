import { CliUsageError } from "../errors.js";

export interface ShellCommandOptions {
  workspace?: string;
  load?: string;
  exclude?: string;
  target?: string;
  scope?: string;
  model?: string;
  effort?: string;
  taskConfig?: string[];
  apiKey?: string;
  authToken?: string;
}

export async function runShellCommand(_opts: ShellCommandOptions): Promise<void> {
  throw new CliUsageError(
    "The TypeScript/Ink shell is retained as reference-only code and is no longer executable through src/cli.ts.\n" +
      "  Use the Rust shell instead: pnpm dev -- shell, cargo run -p kuzushi-cli -- shell, or node bin/kuzushi-rs.mjs shell.",
  );
}

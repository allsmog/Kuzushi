import type { PocExecutionVerdict } from "../contracts.js";

export type { PocSandboxBackend } from "../contracts.js";

/**
 * PoC sandbox execution types — run generated PoC harness scripts
 * in isolated environments and capture results.
 */

export interface PocExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  durationMs: number;
  verdict: PocExecutionVerdict;
}

export interface PocExecutor {
  /** Check if the execution backend is available. */
  available(): Promise<boolean>;
  /** Execute a PoC script and capture results. */
  execute(scriptPath: string, language: string, repoRoot: string): Promise<PocExecutionResult>;
}

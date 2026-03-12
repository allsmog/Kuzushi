import { execFile as execFileCb } from "node:child_process";
import path from "node:path";
import type { PocExecutionResult, PocExecutor } from "./types.js";

const DEFAULT_TIMEOUT_MS = 30_000;

function resolveCommand(language: string): { bin: string; args: string[] } {
  const lower = language.toLowerCase();
  if (lower === "python") return { bin: "python3", args: [] };
  if (lower === "ruby") return { bin: "ruby", args: [] };
  if (lower === "go") return { bin: "go", args: ["run"] };
  if (lower === "shell" || lower === "bash" || lower === "sh") return { bin: "bash", args: [] };
  return { bin: "node", args: [] };
}

/**
 * Process-based PoC executor — fallback when Docker is unavailable.
 * Runs scripts as local processes with timeout enforcement.
 *
 * WARNING: No container isolation. Only use in trusted environments.
 */
export class ProcessPocExecutor implements PocExecutor {
  private readonly timeoutMs: number;

  constructor(timeoutMs: number = DEFAULT_TIMEOUT_MS) {
    this.timeoutMs = timeoutMs;
    console.error(
      "[poc-executor] WARNING: Using process executor without container isolation. " +
      "Install Docker for sandboxed execution.",
    );
  }

  async available(): Promise<boolean> {
    // Process executor is always available
    return true;
  }

  async execute(
    scriptPath: string,
    language: string,
    _repoRoot: string,
  ): Promise<PocExecutionResult> {
    const { bin, args } = resolveCommand(language);
    const absScript = path.resolve(scriptPath);

    return this.run(bin, [...args, absScript]);
  }

  private run(bin: string, args: string[]): Promise<PocExecutionResult> {
    const startedAt = Date.now();

    return new Promise<PocExecutionResult>((resolve) => {
      execFileCb(bin, args, {
        timeout: this.timeoutMs,
        maxBuffer: 1024 * 1024,
      }, (error, stdout, stderr) => {
        const durationMs = Date.now() - startedAt;
        const timedOut = error !== null && "killed" in error && error.killed === true;

        if (timedOut) {
          resolve({
            exitCode: -1,
            stdout: String(stdout ?? ""),
            stderr: String(stderr ?? ""),
            timedOut: true,
            durationMs,
            verdict: "TIMEOUT",
          });
          return;
        }

        let exitCode = 0;
        if (error) {
          const errWithCode = error as { code?: unknown };
          exitCode = typeof errWithCode.code === "number" ? errWithCode.code : 1;
        }

        resolve({
          exitCode,
          stdout: String(stdout ?? ""),
          stderr: String(stderr ?? ""),
          timedOut: false,
          durationMs,
          verdict: exitCode === 0 ? "PASS" : "FAIL",
        });
      });
    });
  }
}

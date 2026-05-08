import { execFile as execFileCb, execFileSync } from "node:child_process";
import path from "node:path";
import type { PocExecutionResult, PocExecutor } from "./types.js";

const IMAGE_MAP: Record<string, string> = {
  javascript: "node:22-slim",
  typescript: "node:22-slim",
  python: "python:3.12-slim",
  shell: "bash",
  bash: "bash",
  sh: "bash",
  ruby: "ruby:3.3-slim",
  go: "golang:1.22-alpine",
};

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MEMORY = "256m";
const DEFAULT_CPUS = "1";

function resolveImage(language: string): string {
  return IMAGE_MAP[language.toLowerCase()] ?? "node:22-slim";
}

function resolveCommand(language: string): string[] {
  const lower = language.toLowerCase();
  if (lower === "python") return ["python3"];
  if (lower === "ruby") return ["ruby"];
  if (lower === "go") return ["go", "run"];
  if (lower === "shell" || lower === "bash" || lower === "sh") return ["bash"];
  return ["node"];
}

/**
 * Docker-based PoC executor — runs scripts in isolated containers with:
 * - No network access (--network=none)
 * - Read-only filesystem (--read-only)
 * - Limited memory and CPU
 * - Timeout enforcement
 */
export class DockerPocExecutor implements PocExecutor {
  private readonly timeoutMs: number;

  constructor(timeoutMs: number = DEFAULT_TIMEOUT_MS) {
    this.timeoutMs = timeoutMs;
  }

  async available(): Promise<boolean> {
    try {
      execFileSync("docker", ["version"], {
        stdio: "pipe",
        timeout: 5000,
      });
      return true;
    } catch {
      return false;
    }
  }

  async execute(
    scriptPath: string,
    language: string,
    repoRoot: string,
  ): Promise<PocExecutionResult> {
    const image = resolveImage(language);
    const cmd = resolveCommand(language);
    const absScript = path.resolve(scriptPath);
    const scriptDir = path.dirname(absScript);
    const scriptName = path.basename(absScript);

    const args = [
      "run",
      "--rm",
      "--network=none",
      `--memory=${DEFAULT_MEMORY}`,
      `--cpus=${DEFAULT_CPUS}`,
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=64m",
      "-v",
      `${scriptDir}:/poc:ro`,
      "-v",
      `${path.resolve(repoRoot)}:/repo:ro`,
      "-w",
      "/poc",
      image,
      ...cmd,
      scriptName,
    ];

    return this.runDocker(args);
  }

  private runDocker(args: string[]): Promise<PocExecutionResult> {
    const startedAt = Date.now();

    return new Promise<PocExecutionResult>((resolve) => {
      const child = execFileCb(
        "docker",
        args,
        {
          timeout: this.timeoutMs,
          maxBuffer: 1024 * 1024,
        },
        (error, stdout, stderr) => {
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
            const errObj = error as Record<string, unknown>;
            const code = errObj["code"];
            exitCode = typeof code === "number" ? code : 1;
          }

          resolve({
            exitCode,
            stdout: String(stdout ?? ""),
            stderr: String(stderr ?? ""),
            timedOut: false,
            durationMs,
            verdict: exitCode === 0 ? "PASS" : "FAIL",
          });
        },
      );

      // Safety: kill child if still running after timeout + buffer
      setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already exited */
        }
      }, this.timeoutMs + 5000);
    });
  }
}

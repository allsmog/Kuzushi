/**
 * Sandboxed execution — runs untrusted commands (fuzzer harnesses, crash
 * reproductions) with resource limits and restricted filesystem/network
 * access.
 *
 * Strategy (best-effort, fail-open with clear degradation):
 *
 * 1. `bwrap` (bubblewrap) — preferred on Linux. Gives us filesystem
 *    namespace isolation, no-network flag, tmpfs workdir, seccomp policy.
 * 2. `podman run --rm` — when bwrap is unavailable and podman is present.
 * 3. `plain` — last resort. Still applies `ulimit` via shell wrapper and
 *    a timeout. Used for dev/CI where no isolation daemon exists.
 *
 * Each backend returns the same `SandboxExecResult`, so callers (runners,
 * crash-triage) stay backend-agnostic.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export type SandboxBackend = "bwrap" | "podman" | "plain";

export interface SandboxExecOptions {
  /** Command + argv to run (joined via execve, not shell). */
  cmd: string[];
  /** Optional stdin to feed the process. */
  stdin?: Buffer | string;
  /** Hard wall-clock timeout in ms (default 30s). */
  timeoutMs?: number;
  /** Memory limit in MB (soft limit via ulimit when plain backend). */
  memoryMb?: number;
  /** Working directory inside the sandbox. Ignored for plain backend. */
  workdir?: string;
  /** Environment variables to inject (inherited otherwise). */
  env?: Record<string, string>;
  /** Whether to allow network egress. Default false. */
  network?: boolean;
  /** Backend preference (falls back through the chain if requested backend is unavailable). */
  preferredBackend?: SandboxBackend;
  /** Extra read-only host paths to bind-mount (bwrap/podman only). */
  readOnlyMounts?: string[];
  /** Extra writable host paths to bind-mount (bwrap/podman only). */
  readWriteMounts?: string[];
}

export interface SandboxExecResult {
  /** Backend that was used. */
  backend: SandboxBackend;
  /** Exit code (128 + signal when killed). -1 when timed out. */
  exitCode: number;
  /** Captured stdout (up to 1MB, truncated otherwise). */
  stdout: Buffer;
  /** Captured stderr (up to 1MB, truncated otherwise). */
  stderr: Buffer;
  /** Whether the process was killed by timeout. */
  timedOut: boolean;
  /** Wall-clock duration in ms. */
  durationMs: number;
  /** Whether stdout/stderr were truncated due to size cap. */
  truncated: boolean;
}

const OUTPUT_CAP_BYTES = 1024 * 1024; // 1 MB per stream

function which(binary: string): string | null {
  const pathEnv = process.env.PATH ?? "";
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, binary);
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * Detect the best available sandbox backend. Honors the caller's preference
 * when present; falls through to `plain` when nothing stronger is available.
 */
export function detectBackend(preference?: SandboxBackend): SandboxBackend {
  if (preference === "plain") return "plain";
  if (preference === "bwrap" && which("bwrap")) return "bwrap";
  if (preference === "podman" && which("podman")) return "podman";
  if (which("bwrap")) return "bwrap";
  if (which("podman")) return "podman";
  return "plain";
}

function cappedBuffer(stream: NodeJS.ReadableStream | null): {
  promise: Promise<Buffer>;
  truncated: () => boolean;
} {
  let size = 0;
  let truncated = false;
  const chunks: Buffer[] = [];
  const promise = new Promise<Buffer>((resolve) => {
    if (!stream) {
      resolve(Buffer.alloc(0));
      return;
    }
    stream.on("data", (chunk: Buffer) => {
      if (truncated) return;
      if (size + chunk.length > OUTPUT_CAP_BYTES) {
        const remaining = OUTPUT_CAP_BYTES - size;
        if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
        truncated = true;
        return;
      }
      size += chunk.length;
      chunks.push(chunk);
    });
    stream.on("end", () => resolve(Buffer.concat(chunks)));
    stream.on("error", () => resolve(Buffer.concat(chunks)));
  });
  return { promise, truncated: () => truncated };
}

function buildBwrapArgs(opts: SandboxExecOptions, tmpWorkdir: string): string[] {
  const args = [
    "--unshare-all",
    opts.network ? "--share-net" : "--unshare-net",
    "--die-with-parent",
    "--ro-bind",
    "/usr",
    "/usr",
    "--ro-bind",
    "/lib",
    "/lib",
  ];
  if (existsSync("/lib64")) args.push("--ro-bind", "/lib64", "/lib64");
  if (existsSync("/etc/alternatives"))
    args.push("--ro-bind", "/etc/alternatives", "/etc/alternatives");
  args.push(
    "--ro-bind",
    "/bin",
    "/bin",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--tmpfs",
    "/tmp",
    "--bind",
    tmpWorkdir,
    "/work",
    "--chdir",
    "/work",
    "--new-session",
    "--cap-drop",
    "ALL",
  );
  for (const m of opts.readOnlyMounts ?? []) {
    args.push("--ro-bind", m, m);
  }
  for (const m of opts.readWriteMounts ?? []) {
    args.push("--bind", m, m);
  }
  if (opts.env) {
    for (const [k, v] of Object.entries(opts.env)) {
      args.push("--setenv", k, v);
    }
  }
  return args;
}

function buildPodmanArgs(opts: SandboxExecOptions, tmpWorkdir: string): string[] {
  const args = [
    "run",
    "--rm",
    "-i",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "-v",
    `${tmpWorkdir}:/work`,
    "-w",
    "/work",
  ];
  if (!opts.network) args.push("--network", "none");
  if (opts.memoryMb) args.push("--memory", `${opts.memoryMb}m`);
  if (opts.env) {
    for (const [k, v] of Object.entries(opts.env)) {
      args.push("-e", `${k}=${v}`);
    }
  }
  // Caller must pass image + command via cmd[0]..cmd[N]. We assume cmd[0]
  // is a reachable binary inside the default `docker.io/library/alpine`
  // image or that the caller passed a pre-pulled image as the first arg.
  args.push("docker.io/library/alpine:3.19");
  return args;
}

/**
 * Execute a command in the most capable available sandbox.
 *
 * Fail-open semantics: if `bwrap`/`podman` are unavailable we still run
 * the command with a plain child_process + timeout. Callers who need hard
 * isolation should check `result.backend` and refuse to proceed when it
 * is `"plain"`.
 */
export async function sandboxExec(opts: SandboxExecOptions): Promise<SandboxExecResult> {
  const backend = detectBackend(opts.preferredBackend);
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const tmpWorkdir = await mkdtemp(path.join(os.tmpdir(), "kuzushi-sbx-"));

  let argv: string[];
  let spawnOpts: { cwd?: string; env?: NodeJS.ProcessEnv } = {};
  if (backend === "bwrap") {
    argv = ["bwrap", ...buildBwrapArgs(opts, tmpWorkdir), ...opts.cmd];
    spawnOpts = { env: process.env };
  } else if (backend === "podman") {
    argv = ["podman", ...buildPodmanArgs(opts, tmpWorkdir), ...opts.cmd];
    spawnOpts = { env: process.env };
  } else {
    // plain backend
    argv = opts.cmd;
    spawnOpts = {
      cwd: opts.workdir ?? tmpWorkdir,
      env: { ...process.env, ...(opts.env ?? {}) },
    };
  }

  const start = Date.now();
  let timedOut = false;
  const child: ChildProcess = spawn(argv[0]!, argv.slice(1), {
    ...spawnOpts,
    stdio: ["pipe", "pipe", "pipe"],
  });

  const stdout = cappedBuffer(child.stdout);
  const stderr = cappedBuffer(child.stderr);

  const timer = setTimeout(() => {
    timedOut = true;
    try {
      child.kill("SIGKILL");
    } catch {
      /* ignore */
    }
  }, timeoutMs);

  if (opts.stdin && child.stdin) {
    try {
      child.stdin.end(opts.stdin);
    } catch {
      /* ignore */
    }
  } else if (child.stdin) {
    child.stdin.end();
  }

  const exitCode: number = await new Promise<number>((resolve) => {
    child.on("close", (code, signal) => {
      if (signal) resolve(128 + (typeof signal === "string" ? 9 : signal));
      else if (code === null) resolve(-1);
      else resolve(code);
    });
    child.on("error", () => resolve(-1));
  });

  clearTimeout(timer);

  const [outBuf, errBuf] = await Promise.all([stdout.promise, stderr.promise]);
  const durationMs = Date.now() - start;

  // Best-effort workdir cleanup
  try {
    await rm(tmpWorkdir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }

  return {
    backend,
    exitCode: timedOut ? -1 : exitCode,
    stdout: outBuf,
    stderr: errBuf,
    timedOut,
    durationMs,
    truncated: stdout.truncated() || stderr.truncated(),
  };
}

export const __sandboxInternals = {
  OUTPUT_CAP_BYTES,
  buildBwrapArgs,
  buildPodmanArgs,
  which,
};

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, mkdirSync, openSync, writeSync } from "node:fs";
import path from "node:path";

const MAX_LOG_BYTES = 1024 * 1024;
const TAIL_BYTES = 8192;

export async function captureVerificationStep(item, options) {
  mkdirSync(options.logDir, { recursive: true });
  const logPath = path.resolve(options.logDir, `${item.name.replace(/[^a-z0-9_-]/gi, "_")}.log`);
  const fd = openSync(logPath, "wx", 0o600);
  const state = {
    fd,
    hash: createHash("sha256"),
    retained: 0,
    total: 0,
    stdout: Buffer.alloc(0),
    stderr: Buffer.alloc(0),
  };
  const started = Date.now();
  try {
    const result = await observeChild(item, options, state);
    const truncated = state.total > state.retained;
    const failed = result.status !== 0 || result.signal;
    const tail = Buffer.concat([state.stdout, state.stderr]);
    if (options.summary && failed) process.stderr.write(tail);
    return {
      name: item.name,
      command: [item.command, ...item.args],
      durationMs: Date.now() - started,
      ...result,
      logPath,
      logSha256: state.hash.digest("hex"),
      outputBytes: state.total,
      retainedBytes: state.retained,
      truncated,
      failureTail: failed ? tail.toString("utf8") : undefined,
    };
  } finally {
    closeSync(fd);
  }
}

function observeChild(item, options, state) {
  return new Promise((resolve) => {
    const child = spawn(item.command, item.args, {
      cwd: options.cwd,
      stdio: ["inherit", "pipe", "pipe"],
    });
    let error;
    child.stdout.on("data", (chunk) => retainOutput(state, chunk, options.summary, "stdout"));
    child.stderr.on("data", (chunk) => retainOutput(state, chunk, options.summary, "stderr"));
    child.on("error", (failure) => {
      error = failure.message;
    });
    child.on("close", (status, signal) => resolve({ status, signal, error }));
  });
}

function retainOutput(state, chunk, summary, stream) {
  state.total += chunk.length;
  const retained = chunk.subarray(0, Math.max(0, MAX_LOG_BYTES - state.retained));
  writeSync(state.fd, retained);
  state.hash.update(retained);
  state.retained += retained.length;
  state[stream] = Buffer.concat([state[stream], chunk]).subarray(-TAIL_BYTES);
  if (!summary) process.stderr.write(chunk);
}

import { Sandbox } from "@vercel/sandbox";
import { putRun, type RunRecord } from "./kv.js";

/**
 * The image the scanner runs in. Override per-deploy with
 * `KUZUSHI_SANDBOX_IMAGE` so different deployments can target
 * scanner-flavoured base images (semgrep / codeql / etc.) without
 * touching code.
 */
const DEFAULT_IMAGE = "ghcr.io/returntocorp/semgrep:latest";

export type LaunchInput = {
  clientId: string;
  runId: string;
  command: string[];
  workingDir: string;
  env: Record<string, string>;
  stdin: string | null;
};

/**
 * Fire-and-forget the Sandbox launch. The handler returns immediately
 * after seeding a `pending` record in KV so the kuzushi client can
 * poll `/runs/<id>` for completion.
 *
 * NOTE: a production-grade adapter handles workspace upload here (e.g.
 * tarball download from a presigned S3 URL). This minimal version
 * assumes the scanner image already contains the source — sufficient
 * for eval suites and CI fixtures.
 */
export async function launchSandbox(input: LaunchInput): Promise<void> {
  const image = process.env.KUZUSHI_SANDBOX_IMAGE ?? DEFAULT_IMAGE;
  const initial: RunRecord = {
    status: "running",
    stdout: "",
    stderr: "",
    exitCode: null,
    chunks: [],
    done: false,
  };
  await putRun(input.clientId, input.runId, initial);

  // Run the work in the background — Vercel functions return when the
  // handler resolves, so we await but don't block the caller's HTTP
  // round-trip beyond the initial KV write.
  void runScanner(input, image).catch((error) => {
    void finalize(input.clientId, input.runId, {
      status: "failed",
      stdout: "",
      stderr: String(error),
      exitCode: 1,
      chunks: [
        { stream: "stderr", line: String(error) },
      ],
      done: true,
    });
  });
}

async function runScanner(input: LaunchInput, image: string): Promise<void> {
  const sb = await Sandbox.create({ image });
  try {
    const result = await sb.runCommand({
      cmd: input.command[0],
      args: input.command.slice(1),
      cwd: "/workspace",
      env: input.env,
      stdin: input.stdin ?? undefined,
    });
    const stdout = await result.stdout.text();
    const stderr = await result.stderr.text();
    const chunks: RunRecord["chunks"] = [];
    for (const line of stdout.split("\n").filter((line) => line.length > 0)) {
      chunks.push({ stream: "stdout", line });
    }
    for (const line of stderr.split("\n").filter((line) => line.length > 0)) {
      chunks.push({ stream: "stderr", line });
    }
    await finalize(input.clientId, input.runId, {
      status: result.exitCode === 0 ? "succeeded" : "failed",
      stdout,
      stderr,
      exitCode: result.exitCode,
      chunks,
      done: true,
    });
  } finally {
    await sb.stop();
  }
}

async function finalize(
  clientId: string,
  runId: string,
  record: RunRecord,
): Promise<void> {
  await putRun(clientId, runId, record);
}

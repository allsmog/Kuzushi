import { DockerPocExecutor } from "./docker.js";
import { ProcessPocExecutor } from "./process.js";
import type { PocExecutor, PocSandboxBackend } from "./types.js";
import { getLogger } from "../logger.js";

export type { PocExecutionResult, PocExecutor, PocSandboxBackend } from "./types.js";
export { DockerPocExecutor } from "./docker.js";
export { ProcessPocExecutor } from "./process.js";

const log = getLogger("poc-executor");

/**
 * Create a PoC executor for the requested backend.
 * If backend is "docker", Docker must be available.
 * If backend is "process", uses process directly.
 */
export async function createPocExecutor(
  backend: PocSandboxBackend = "docker",
  timeoutMs?: number,
): Promise<PocExecutor> {
  if (backend === "process") {
    return new ProcessPocExecutor(timeoutMs);
  }

  const docker = new DockerPocExecutor(timeoutMs);
  if (await docker.available()) {
    return docker;
  }

  log.warn("Docker sandbox requested but Docker is unavailable");
  throw new Error(
    "Docker sandbox requested but Docker is unavailable. Install Docker or set pocSandbox=process explicitly.",
  );
}

import { DockerPocExecutor } from "./docker.js";
import { ProcessPocExecutor } from "./process.js";
import type { PocExecutor, PocSandboxBackend } from "./types.js";

export type { PocExecutionResult, PocExecutor, PocSandboxBackend } from "./types.js";
export { DockerPocExecutor } from "./docker.js";
export { ProcessPocExecutor } from "./process.js";

/**
 * Create a PoC executor with Docker-preferred fallback to process.
 * If backend is "docker", tries Docker first, falls back to process.
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

  console.error(
    "[poc-executor] Docker not available, falling back to process executor",
  );
  return new ProcessPocExecutor(timeoutMs);
}

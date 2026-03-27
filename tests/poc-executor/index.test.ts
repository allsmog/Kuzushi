import { beforeEach, describe, expect, it, vi } from "vitest";
import { createPocExecutor } from "../../src/poc-executor/index.js";
import { DockerPocExecutor } from "../../src/poc-executor/docker.js";
import { ProcessPocExecutor } from "../../src/poc-executor/process.js";

describe("createPocExecutor", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns a process executor when requested explicitly", async () => {
    const executor = await createPocExecutor("process");
    expect(executor).toBeInstanceOf(ProcessPocExecutor);
  });

  it("returns a docker executor when Docker is available", async () => {
    vi.spyOn(DockerPocExecutor.prototype, "available").mockResolvedValue(true);

    const executor = await createPocExecutor("docker");
    expect(executor).toBeInstanceOf(DockerPocExecutor);
  });

  it("throws when Docker is requested but unavailable", async () => {
    vi.spyOn(DockerPocExecutor.prototype, "available").mockResolvedValue(false);

    await expect(createPocExecutor("docker")).rejects.toThrow(
      "Docker sandbox requested but Docker is unavailable",
    );
  });
});

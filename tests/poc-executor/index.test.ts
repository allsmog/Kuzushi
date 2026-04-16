import { beforeEach, describe, expect, it, vi } from "vitest";
import { DockerPocExecutor } from "../../src/poc-executor/docker.js";
import { createPocExecutor } from "../../src/poc-executor/index.js";
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

  it("falls back to process executor when Docker is unavailable", async () => {
    vi.spyOn(DockerPocExecutor.prototype, "available").mockResolvedValue(false);

    const executor = await createPocExecutor("docker");
    expect(executor).toBeInstanceOf(ProcessPocExecutor);
  });
});

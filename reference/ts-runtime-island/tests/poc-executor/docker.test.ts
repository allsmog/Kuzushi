import { beforeEach, describe, expect, it, vi } from "vitest";
import { DockerPocExecutor } from "../../src/poc-executor/docker.js";

// Mock child_process
vi.mock("node:child_process", () => ({
  execFileSync: vi.fn(),
  execFile: vi.fn(),
}));

import { execFile, execFileSync } from "node:child_process";

describe("DockerPocExecutor", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("available", () => {
    it("returns true when docker version succeeds", async () => {
      vi.mocked(execFileSync).mockReturnValue(Buffer.from("Docker version 24.0"));
      const executor = new DockerPocExecutor();
      expect(await executor.available()).toBe(true);
      expect(execFileSync).toHaveBeenCalledWith("docker", ["version"], expect.any(Object));
    });

    it("returns false when docker version fails", async () => {
      vi.mocked(execFileSync).mockImplementation(() => {
        throw new Error("docker not found");
      });
      const executor = new DockerPocExecutor();
      expect(await executor.available()).toBe(false);
    });
  });

  describe("execute", () => {
    it("constructs correct docker command for JavaScript", async () => {
      vi.mocked(execFile).mockImplementation((_cmd, args, _opts, callback) => {
        if (callback) {
          (callback as (...args: unknown[]) => unknown)(null, "PASS", "");
        }
        return { kill: vi.fn() } as any;
      });

      const executor = new DockerPocExecutor(30000);
      const result = await executor.execute("/tmp/poc/test.js", "javascript", "/repo");

      expect(result.verdict).toBe("PASS");
      expect(result.exitCode).toBe(0);
      expect(result.timedOut).toBe(false);

      const dockerArgs = vi.mocked(execFile).mock.calls[0][1] as string[];
      expect(dockerArgs).toContain("--network=none");
      expect(dockerArgs).toContain("--read-only");
      expect(dockerArgs).toContain("node:22-slim");
      expect(dockerArgs).toContain("node");
    });

    it("constructs correct docker command for Python", async () => {
      vi.mocked(execFile).mockImplementation((_cmd, args, _opts, callback) => {
        if (callback) {
          (callback as (...args: unknown[]) => unknown)(null, "output", "");
        }
        return { kill: vi.fn() } as any;
      });

      const executor = new DockerPocExecutor();
      await executor.execute("/tmp/poc/test.py", "python", "/repo");

      const dockerArgs = vi.mocked(execFile).mock.calls[0][1] as string[];
      expect(dockerArgs).toContain("python:3.12-slim");
      expect(dockerArgs).toContain("python3");
    });

    it("reports FAIL for non-zero exit code", async () => {
      vi.mocked(execFile).mockImplementation((_cmd, _args, _opts, callback) => {
        if (callback) {
          const error = Object.assign(new Error("exit 1"), { code: 1 });
          (callback as (...args: unknown[]) => unknown)(error, "", "error output");
        }
        return { kill: vi.fn() } as any;
      });

      const executor = new DockerPocExecutor();
      const result = await executor.execute("/tmp/poc/test.js", "javascript", "/repo");

      expect(result.verdict).toBe("FAIL");
      expect(result.stderr).toBe("error output");
    });

    it("reports TIMEOUT when process is killed", async () => {
      vi.mocked(execFile).mockImplementation((_cmd, _args, _opts, callback) => {
        if (callback) {
          const error = Object.assign(new Error("killed"), { killed: true });
          (callback as (...args: unknown[]) => unknown)(error, "", "");
        }
        return { kill: vi.fn() } as any;
      });

      const executor = new DockerPocExecutor(5000);
      const result = await executor.execute("/tmp/poc/test.js", "javascript", "/repo");

      expect(result.verdict).toBe("TIMEOUT");
      expect(result.timedOut).toBe(true);
    });
  });
});

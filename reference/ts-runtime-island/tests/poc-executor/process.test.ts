import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProcessPocExecutor } from "../../src/poc-executor/process.js";

vi.mock("node:child_process", () => ({
  execFile: vi.fn(),
}));

import { execFile } from "node:child_process";

describe("ProcessPocExecutor", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("available", () => {
    it("always returns true", async () => {
      const executor = new ProcessPocExecutor();
      expect(await executor.available()).toBe(true);
    });
  });

  describe("execute", () => {
    it("returns PASS for exit code 0", async () => {
      vi.mocked(execFile).mockImplementation((_cmd, _args, _opts, callback) => {
        if (callback) {
          (callback as (...args: unknown[]) => unknown)(null, "success", "");
        }
        return undefined as any;
      });

      const executor = new ProcessPocExecutor(30000);
      const result = await executor.execute("/tmp/test.js", "javascript", "/repo");

      expect(result.verdict).toBe("PASS");
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toBe("success");
      expect(result.timedOut).toBe(false);
    });

    it("returns FAIL for non-zero exit code", async () => {
      vi.mocked(execFile).mockImplementation((_cmd, _args, _opts, callback) => {
        if (callback) {
          const error = Object.assign(new Error("exit 1"), { code: 1 });
          (callback as (...args: unknown[]) => unknown)(error, "", "error");
        }
        return undefined as any;
      });

      const executor = new ProcessPocExecutor();
      const result = await executor.execute("/tmp/test.py", "python", "/repo");

      expect(result.verdict).toBe("FAIL");
      expect(result.stderr).toBe("error");
    });

    it("returns TIMEOUT when killed", async () => {
      vi.mocked(execFile).mockImplementation((_cmd, _args, _opts, callback) => {
        if (callback) {
          const error = Object.assign(new Error("killed"), { killed: true });
          (callback as (...args: unknown[]) => unknown)(error, "", "");
        }
        return undefined as any;
      });

      const executor = new ProcessPocExecutor(5000);
      const result = await executor.execute("/tmp/test.sh", "shell", "/repo");

      expect(result.verdict).toBe("TIMEOUT");
      expect(result.timedOut).toBe(true);
    });

    it("resolves correct binary for different languages", async () => {
      vi.mocked(execFile).mockImplementation((cmd, args, _opts, callback) => {
        if (callback) {
          (callback as (...args: unknown[]) => unknown)(null, `ran: ${cmd} ${args}`, "");
        }
        return undefined as any;
      });

      const executor = new ProcessPocExecutor();

      await executor.execute("/tmp/test.py", "python", "/repo");
      expect(vi.mocked(execFile).mock.calls[0][0]).toBe("python3");

      await executor.execute("/tmp/test.rb", "ruby", "/repo");
      expect(vi.mocked(execFile).mock.calls[1][0]).toBe("ruby");

      await executor.execute("/tmp/test.sh", "bash", "/repo");
      expect(vi.mocked(execFile).mock.calls[2][0]).toBe("bash");
    });
  });
});

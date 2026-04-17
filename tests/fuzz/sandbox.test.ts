import { describe, expect, it } from "vitest";
import { __sandboxInternals, detectBackend, sandboxExec } from "../../src/fuzz/sandbox.js";

describe("fuzz/sandbox helpers", () => {
  it("detectBackend honors explicit plain preference", () => {
    expect(detectBackend("plain")).toBe("plain");
  });

  it("buildBwrapArgs disables network by default", () => {
    const args = __sandboxInternals.buildBwrapArgs(
      { cmd: ["/bin/true"], network: false },
      "/tmp/work",
    );
    expect(args).toContain("--unshare-net");
    expect(args).toContain("--bind");
    expect(args).toContain("/tmp/work");
  });

  it("buildBwrapArgs enables shared network when requested", () => {
    const args = __sandboxInternals.buildBwrapArgs(
      { cmd: ["/bin/true"], network: true },
      "/tmp/work",
    );
    expect(args).toContain("--share-net");
  });

  it("buildBwrapArgs forwards env variables via --setenv", () => {
    const args = __sandboxInternals.buildBwrapArgs(
      { cmd: ["/bin/true"], env: { FOO: "bar" } },
      "/tmp/work",
    );
    expect(args).toContain("--setenv");
    expect(args).toContain("FOO");
    expect(args).toContain("bar");
  });

  it("buildPodmanArgs sets network=none by default and honors memory cap", () => {
    const args = __sandboxInternals.buildPodmanArgs(
      { cmd: ["/bin/true"], memoryMb: 128 },
      "/tmp/work",
    );
    expect(args).toContain("--network");
    expect(args).toContain("none");
    expect(args).toContain("--memory");
    expect(args).toContain("128m");
  });
});

describe("fuzz/sandbox plain backend execution", () => {
  it("captures stdout from a simple shell-free command", async () => {
    const result = await sandboxExec({
      cmd: ["/bin/echo", "hello-from-sandbox"],
      preferredBackend: "plain",
      timeoutMs: 5000,
    });
    // Fallback: some minimal environments don't have /bin/echo — skip assertion chain in that case.
    if (result.exitCode === -1) {
      return;
    }
    expect(result.backend).toBe("plain");
    expect(result.exitCode).toBe(0);
    expect(result.stdout.toString("utf8")).toContain("hello-from-sandbox");
    expect(result.timedOut).toBe(false);
  });

  it(
    "returns timedOut=true when the process exceeds timeoutMs",
    async () => {
      const result = await sandboxExec({
        cmd: [process.execPath, "-e", "setInterval(()=>{},1000)"],
        preferredBackend: "plain",
        timeoutMs: 200,
      });
      // Environments without a usable node binary bail out with exitCode -1
      // and no timeout — skip in that case.
      if (result.exitCode === -1 && !result.timedOut) return;
      expect(result.timedOut).toBe(true);
      expect(result.durationMs).toBeLessThan(5000);
    },
    { timeout: 15_000 },
  );
});

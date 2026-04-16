import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createLogger, getGlobalLogLevel, redactString, setGlobalLogLevel } from "../src/logger.js";

describe("logger", () => {
  const originalLevel = getGlobalLogLevel();

  beforeEach(() => {
    setGlobalLogLevel("info");
  });

  afterEach(() => {
    setGlobalLogLevel(originalLevel);
    vi.restoreAllMocks();
  });

  it("suppresses warn logs when level is set to error", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const log = createLogger({ stage: "test" });

    setGlobalLogLevel("error");
    log.warn("hidden warning");
    log.error("visible error");

    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0]?.[0]).toContain("[test] [error]");
  });

  it("redacts API-like secrets from log strings", () => {
    expect(redactString("token sk-ant-abcdefghijklmnopqrstuvwxyz0123456789")).toContain(
      "sk-ant...6789",
    );
  });
});

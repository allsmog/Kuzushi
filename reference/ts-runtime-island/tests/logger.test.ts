import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createLogger,
  getGlobalLogFormat,
  getGlobalLogLevel,
  redactString,
  setGlobalLogFormat,
  setGlobalLogLevel,
} from "../src/logger.js";

describe("logger", () => {
  const originalLevel = getGlobalLogLevel();
  const originalFormat = getGlobalLogFormat();

  beforeEach(() => {
    setGlobalLogLevel("info");
    setGlobalLogFormat("text");
  });

  afterEach(() => {
    setGlobalLogLevel(originalLevel);
    setGlobalLogFormat(originalFormat);
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

  it("emits parseable JSON lines in json format", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    setGlobalLogFormat("json");
    const log = createLogger({ stage: "scan" });

    log.info({ runId: "run-1", count: 3 }, "scan started");

    expect(spy).toHaveBeenCalledTimes(1);
    const line = spy.mock.calls[0]?.[0] as string;
    const parsed = JSON.parse(line);
    expect(parsed.level).toBe("info");
    expect(parsed.stage).toBe("scan");
    expect(parsed.msg).toBe("scan started");
    expect(parsed.runId).toBe("run-1");
    expect(parsed.count).toBe(3);
    expect(typeof parsed.time).toBe("string");
  });

  it("redacts secrets inside json-format log fields", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    setGlobalLogFormat("json");
    const log = createLogger({ stage: "auth" });

    log.info("using sk-ant-abcdefghijklmnopqrstuvwxyz0123456789 for auth");

    const line = spy.mock.calls[0]?.[0] as string;
    const parsed = JSON.parse(line);
    expect(parsed.msg).not.toContain("sk-ant-abcdefghijklmnopqrstuvwxyz0123456789");
    expect(parsed.msg).toContain("sk-ant...6789");
  });
});

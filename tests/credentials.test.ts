import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { __resetApiKeyWarnings, resolveAgentRuntimeConfig } from "../src/credentials.js";

describe("resolveAgentRuntimeConfig", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-creds-"));
    __resetApiKeyWarnings();
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns undefined when no config is provided", () => {
    expect(resolveAgentRuntimeConfig(undefined)).toBeUndefined();
  });

  it("passes through an inline apiKey unchanged", () => {
    const result = resolveAgentRuntimeConfig({ apiKey: "sk-ant-inline" });
    expect(result).toEqual({ apiKey: "sk-ant-inline" });
  });

  it("populates apiKey from apiKeyFile when only the file is set", () => {
    const keyPath = path.join(tmpDir, "key");
    writeFileSync(keyPath, "sk-ant-from-file\n", { mode: 0o600 });
    chmodSync(keyPath, 0o600);

    const result = resolveAgentRuntimeConfig({ apiKeyFile: keyPath });

    expect(result?.apiKey).toBe("sk-ant-from-file");
    expect(result?.apiKeyFile).toBe(keyPath);
  });

  it("prefers inline apiKey over apiKeyFile", () => {
    const keyPath = path.join(tmpDir, "key");
    writeFileSync(keyPath, "file-key");
    const result = resolveAgentRuntimeConfig({
      apiKey: "inline-key",
      apiKeyFile: keyPath,
    });
    expect(result?.apiKey).toBe("inline-key");
  });

  it("does not populate apiKey when apiKeyFile is missing", () => {
    const missingPath = path.join(tmpDir, "does-not-exist");
    const result = resolveAgentRuntimeConfig({ apiKeyFile: missingPath });
    expect(result?.apiKey).toBeUndefined();
  });

  it("does not populate apiKey when apiKeyFile is empty", () => {
    const keyPath = path.join(tmpDir, "empty");
    writeFileSync(keyPath, "   \n");
    const result = resolveAgentRuntimeConfig({ apiKeyFile: keyPath });
    expect(result?.apiKey).toBeUndefined();
  });

  it("trims whitespace from the key file contents", () => {
    const keyPath = path.join(tmpDir, "padded");
    writeFileSync(keyPath, "  sk-ant-padded  \n\n");
    const result = resolveAgentRuntimeConfig({ apiKeyFile: keyPath });
    expect(result?.apiKey).toBe("sk-ant-padded");
  });

  it("preserves baseUrl alongside resolved apiKey", () => {
    const keyPath = path.join(tmpDir, "key-with-base");
    writeFileSync(keyPath, "sk-ant-base");
    const result = resolveAgentRuntimeConfig({
      apiKeyFile: keyPath,
      baseUrl: "https://proxy.example/",
    });
    expect(result).toEqual({
      apiKey: "sk-ant-base",
      apiKeyFile: keyPath,
      baseUrl: "https://proxy.example/",
    });
  });
});

import {
  chmodSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error -- plain .mjs bridge module without type declarations
import { debugDumpBridgeCall } from "../../scripts/langgraph-bridge/diagnostics.mjs";

const priorDump = process.env.KUZUSHI_BRIDGE_DEBUG_DUMP;
const priorFullPrompt = process.env.KUZUSHI_BRIDGE_DEBUG_FULL_PROMPT;
const roots: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  restoreEnv("KUZUSHI_BRIDGE_DEBUG_DUMP", priorDump);
  restoreEnv("KUZUSHI_BRIDGE_DEBUG_FULL_PROMPT", priorFullPrompt);
  while (roots.length) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("bridge diagnostics", () => {
  it("writes metadata-only 0600 diagnostics through both compatibility surfaces", () => {
    const root = mkdtempSync(path.join(tmpdir(), "kuzushi-bridge-diagnostics-"));
    roots.push(root);
    const dump = path.join(root, "bridge.jsonl");
    const promptRoot = path.join(root, "prompt-metadata");
    writeFileSync(dump, "", { mode: 0o666 });
    chmodSync(dump, 0o666);
    process.env.KUZUSHI_BRIDGE_DEBUG_DUMP = dump;
    process.env.KUZUSHI_BRIDGE_DEBUG_FULL_PROMPT = promptRoot;
    const sentinel = "hidden-prompt-response-tool-sentinel";

    debugDumpBridgeCall(
      "query",
      { model: "anthropic:configured", prompt: sentinel, messages: [{ content: sentinel }] },
      [{ name: sentinel }],
      sentinel,
      {
        content: sentinel,
        tool_calls: [{ name: sentinel }],
        response_metadata: { finish_reason: sentinel },
      },
    );

    const promptFile = path.join(promptRoot, readdirSync(promptRoot)[0]);
    const bodies = [readFileSync(dump, "utf8"), readFileSync(promptFile, "utf8")];
    expect(bodies.every((body) => !body.includes(sentinel))).toBe(true);
    expect(bodies.map((body) => JSON.parse(body).promptLen)).toEqual([36, 36]);
    expect(fileMode(dump)).toBe(0o600);
    expect(fileMode(promptFile)).toBe(0o600);
  });

  it("honors request-scoped metadata-only verbose and log options", () => {
    const root = mkdtempSync(path.join(tmpdir(), "kuzushi-bridge-runtime-diagnostics-"));
    roots.push(root);
    const log = path.join(root, "bridge.jsonl");
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const sentinel = "request-scoped-secret-sentinel";

    debugDumpBridgeCall(
      "query",
      {
        model: "openai:configured",
        prompt: sentinel,
        runtimeOptions: { bridgeVerbose: true, bridgeLogPath: log },
      },
      [{ name: sentinel }],
      sentinel,
      { content: sentinel },
    );

    const persisted = readFileSync(log, "utf8");
    const emitted = String(stderr.mock.calls[0]?.[0]);
    expect(persisted).not.toContain(sentinel);
    expect(emitted).not.toContain(sentinel);
    expect(JSON.parse(persisted).modelProvider).toBe("openai");
    expect(fileMode(log)).toBe(0o600);
  });
});

function fileMode(file: string) {
  return statSync(file).mode & 0o777;
}

function restoreEnv(name: string, value: string | undefined) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

/**
 * context KB integration: verifies that operator-staged attachments are
 * loaded by `contextEnricherTask.run` from `.kuzushi/context/attachments.json`
 * (under the project repoRoot), rendered into a nonce-wrapped block, and
 * placed inside the system prompt right after the heuristic repo context.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { AgentMessage, AgentRuntime } from "../../../src/agent-runtime/types.js";
import {
  __contextEnricherInternals,
  contextEnricherTask,
} from "../../../src/agents/tasks/context-enricher.js";
import type { TaskContext } from "../../../src/agents/types.js";
import { defaultAttachmentAdapter } from "../../../src/modules/_shared/attachments/index.js";
import { createContextModule } from "../../../src/modules/context/context.js";
import type { KuzushiConfig } from "../../../src/types.js";

const { buildPrompt } = __contextEnricherInternals;

const tempDirs: string[] = [];

function tempRoot(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "ctx-attachments-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
  } as KuzushiConfig;
}

describe("context buildPrompt attachments wiring", () => {
  it("inserts the rendered attachments block right after the heuristic repo context", () => {
    const block = `<untrusted_attachment moduleId="context" nonce="aaaa">payload</untrusted_attachment moduleId="context" nonce="aaaa">`;
    const prompt = buildPrompt(
      {
        languages: ["TypeScript"],
        frameworks: ["Express"],
        authPatterns: ["JWT"],
        sanitizationLibs: ["DOMPurify"],
        ormOrDb: ["Prisma"],
        entryPoints: ["src/index.ts"],
      },
      block,
    );
    const repoIdx = prompt.indexOf("Heuristic repo context");
    const attachmentsHeaderIdx = prompt.indexOf("Operator-attached reference material");
    const blockIdx = prompt.indexOf("<untrusted_attachment");
    const tasksIdx = prompt.indexOf("Custom middleware discovery");
    expect(repoIdx).toBeGreaterThan(-1);
    expect(attachmentsHeaderIdx).toBeGreaterThan(repoIdx);
    expect(blockIdx).toBeGreaterThan(attachmentsHeaderIdx);
    expect(tasksIdx).toBeGreaterThan(blockIdx);
  });

  it("omits the attachments section entirely when no block is provided", () => {
    const prompt = buildPrompt(undefined, undefined);
    expect(prompt).not.toContain("Operator-attached reference material");
    expect(prompt).not.toContain("<untrusted_attachment");
  });

  it("omits the attachments section when the block is whitespace-only", () => {
    const prompt = buildPrompt(undefined, "   \n  ");
    expect(prompt).not.toContain("Operator-attached reference material");
  });
});

describe("contextEnricherTask.run reads attachments from disk and injects them", () => {
  it("renders attachments from .kuzushi/context/attachments.json and the prompt contains the block", async () => {
    const root = tempRoot();
    const adapter = defaultAttachmentAdapter("context");
    adapter.write(root, [
      {
        id: "abc1234567",
        source: path.join(root, "architecture.md"),
        sourceType: "local",
        kind: "architecture-doc",
        title: "architecture.md",
        status: "parsed",
        extracted: {
          text: "Internal admin API trusts X-Forwarded-User without verification",
          charCount: 60,
          parser: "text",
        },
        parseWarnings: [],
        attachedAt: "2026-04-27T00:00:00.000Z",
      },
    ]);

    let capturedPrompt = "";
    const runtime: AgentRuntime = {
      id: "stub",
      query({ prompt }: { prompt: string }): AsyncIterable<AgentMessage> {
        capturedPrompt = prompt;
        // Yield a single result message that completes the run cleanly.
        return (async function* () {
          yield {
            type: "result",
            subtype: "success",
            result: JSON.stringify({
              customMiddleware: [],
              customSanitizers: [],
              trustBoundaries: [],
              dataClassifications: [],
              architecturalNotes: [],
            }),
            totalCostUsd: 0,
          } as AgentMessage;
        })();
      },
    };

    const ctx: TaskContext = {
      runId: "test-run",
      repoRoot: root,
      repoName: "fixture",
      config: makeConfig(),
      runtime,
      bus: {} as TaskContext["bus"],
      upstreamOutputs: new Map(),
    };

    await contextEnricherTask.run(undefined, ctx);

    expect(capturedPrompt).toContain('<untrusted_attachment moduleId="context"');
    expect(capturedPrompt).toContain("X-Forwarded-User");
    expect(capturedPrompt).toContain("Operator-attached reference material");
  });

  it("omits the attachments block when none are staged on disk", async () => {
    const root = tempRoot();
    let capturedPrompt = "";
    const runtime: AgentRuntime = {
      id: "stub",
      query({ prompt }: { prompt: string }): AsyncIterable<AgentMessage> {
        capturedPrompt = prompt;
        return (async function* () {
          yield {
            type: "result",
            subtype: "success",
            result: JSON.stringify({
              customMiddleware: [],
              customSanitizers: [],
              trustBoundaries: [],
              dataClassifications: [],
              architecturalNotes: [],
            }),
            totalCostUsd: 0,
          } as AgentMessage;
        })();
      },
    };
    const ctx: TaskContext = {
      runId: "test-run",
      repoRoot: root,
      repoName: "fixture",
      config: makeConfig(),
      runtime,
      bus: {} as TaskContext["bus"],
      upstreamOutputs: new Map(),
    };
    await contextEnricherTask.run(undefined, ctx);
    expect(capturedPrompt).not.toContain("<untrusted_attachment");
    expect(capturedPrompt).not.toContain("Operator-attached reference material");
  });
});

describe("context module surface", () => {
  it("registers the four shared attachment tools", () => {
    const names = createContextModule()
      .tools.map((t) => t.name)
      .sort();
    expect(names).toContain("context:attach");
    expect(names).toContain("context:attachments");
    expect(names).toContain("context:detach");
    expect(names).toContain("context:reparse");
    expect(names).toContain("context:build");
  });
});

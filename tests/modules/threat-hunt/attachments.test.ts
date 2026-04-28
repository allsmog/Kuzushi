/**
 * threat-hunt KB integration: verifies that operator-staged attachments are
 * loaded by `resolveConfig` and inserted into the per-actor prompt by
 * `buildScopedPrompt` between the scope-restriction line and the base
 * mission. Existing override paths (`THREAT_HUNT_PROMPT`) still emit the
 * attachments block.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { AgentMessage, AgentRuntime } from "../../../src/agent-runtime/types.js";
import type { DfdElement, StrideThreat } from "../../../src/agents/tasks/threat-modeling/types.js";
import { InProcessBus } from "../../../src/bus/adapters/in-process.js";
import { defaultAttachmentAdapter } from "../../../src/modules/_shared/attachments/index.js";
import {
  __threatHuntInternals,
  createThreatHuntModule,
} from "../../../src/modules/threat-hunt/threat-hunt.js";
import type { ExecutionContext } from "../../../src/modules/types.js";

const { buildScopedPrompt, resolveConfig } = __threatHuntInternals;

const tempDirs: string[] = [];

function tempRoot(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "th-attachments-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fakeActor(): DfdElement {
  return {
    id: "actor:user",
    name: "Unauthenticated User",
    type: "external-entity",
    description: "anonymous internet visitor",
    trustZone: "public",
  } as DfdElement;
}

function fakeThreats(): StrideThreat[] {
  return [];
}

function makeCtx(cwd: string): ExecutionContext {
  const bus = new InProcessBus();
  const runtime: AgentRuntime = {
    id: "stub",
    query(): AsyncIterable<AgentMessage> {
      return (async function* () {})();
    },
  };
  return {
    cwd,
    runtime,
    bus,
    config: {
      model: "anthropic:claude-sonnet-4-6",
      taskConfig: { "threat-hunt": {} },
    } as never,
  } as ExecutionContext;
}

describe("threat-hunt buildScopedPrompt attachments ordering", () => {
  it("inserts the rendered block between the scope-restriction line and the actor mission", () => {
    const block = `<untrusted_attachment moduleId="threat-hunt" nonce="aaaa">payload</untrusted_attachment moduleId="threat-hunt" nonce="aaaa">`;
    const out = buildScopedPrompt(fakeActor(), fakeThreats(), "/repo/src", undefined, block);
    const scopeIdx = out.indexOf("Only examine files under");
    const blockIdx = out.indexOf("<untrusted_attachment");
    const missionIdx = out.indexOf("competing in a CTF");
    expect(scopeIdx).toBeGreaterThan(-1);
    expect(blockIdx).toBeGreaterThan(scopeIdx);
    expect(missionIdx).toBeGreaterThan(blockIdx);
  });

  it("omits the block entirely when attachmentsBlock is empty/whitespace", () => {
    const out = buildScopedPrompt(fakeActor(), fakeThreats(), "/repo/src", undefined, "   ");
    expect(out).not.toContain("<untrusted_attachment");
  });

  it("preserves the block under a THREAT_HUNT_PROMPT override (operator evidence is never dropped)", () => {
    const block = `<untrusted_attachment moduleId="threat-hunt" nonce="bbbb">evidence</untrusted_attachment moduleId="threat-hunt" nonce="bbbb">`;
    const out = buildScopedPrompt(
      fakeActor(),
      fakeThreats(),
      "/repo",
      "OPERATOR-OVERRIDE-PROMPT",
      block,
    );
    expect(out).toContain("Only examine files under /repo");
    expect(out).toContain('<untrusted_attachment moduleId="threat-hunt"');
    expect(out).toContain("OPERATOR-OVERRIDE-PROMPT");
    expect(out).not.toContain("competing in a CTF"); // base prompt was overridden
  });
});

describe("threat-hunt resolveConfig attachments loading", () => {
  it("loads attachments from .kuzushi/threat-hunt/attachments.json and renders them", async () => {
    const root = tempRoot();
    const adapter = defaultAttachmentAdapter("threat-hunt");
    adapter.write(root, [
      {
        id: "deadbeef0001",
        source: path.join(root, "incident.md"),
        sourceType: "local",
        kind: "incident",
        title: "incident.md",
        status: "parsed",
        extracted: {
          text: "Q1 incident — Stripe webhook signature bypass via clock skew",
          charCount: 60,
          parser: "text",
        },
        parseWarnings: [],
        attachedAt: "2026-04-27T00:00:00.000Z",
      },
    ]);

    const ctx = makeCtx(root);
    const config = await resolveConfig({}, ctx);
    expect(config.attachmentsBlock).toBeDefined();
    expect(config.attachmentsBlock!).toContain('<untrusted_attachment moduleId="threat-hunt"');
    expect(config.attachmentsBlock!).toContain("Stripe webhook signature bypass");
  });

  it("does not set attachmentsBlock when no attachments exist", async () => {
    const root = tempRoot();
    const ctx = makeCtx(root);
    const config = await resolveConfig({}, ctx);
    expect(config.attachmentsBlock).toBeUndefined();
  });
});

describe("threat-hunt module surface", () => {
  it("registers the four shared attachment tools alongside threat-hunt:run", () => {
    const names = createThreatHuntModule()
      .tools.map((t) => t.name)
      .sort();
    expect(names).toContain("threat-hunt:attach");
    expect(names).toContain("threat-hunt:attachments");
    expect(names).toContain("threat-hunt:detach");
    expect(names).toContain("threat-hunt:reparse");
    expect(names).toContain("threat-hunt:run");
  });
});

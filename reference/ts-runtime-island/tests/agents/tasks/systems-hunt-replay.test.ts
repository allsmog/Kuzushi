import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type {
  AgentMessage,
  AgentQueryRequest,
  AgentRuntime,
} from "../../../src/agent-runtime/types.js";
import { gatherContextForRoot } from "../../../src/agents/tasks/context-gatherer.js";
import { extractSystemsHuntArtifactPath } from "../../../src/agents/tasks/systems-hunt/artifacts.js";
import { systemsContextGathererTask } from "../../../src/agents/tasks/systems-hunt/context.js";
import { systemsHuntTask } from "../../../src/agents/tasks/systems-hunt/hunt.js";
import { systemsInvariantExtractTask } from "../../../src/agents/tasks/systems-hunt/invariant-extract.js";
import { systemsTriggerSynthTask } from "../../../src/agents/tasks/systems-hunt/trigger-synth.js";
import type { DagRunContext } from "../../../src/agents/types.js";
import { DEFAULTS } from "../../../src/config.js";

const FIXTURE_ROOT = path.resolve("tests/fixtures/systems-hunt");

interface ReplayCase {
  fixture: string;
  shouldFind: boolean;
  expectedPrimitive?: string;
}

const CASES: ReplayCase[] = [
  {
    fixture: "protocol-wraparound-positive",
    shouldFind: true,
    expectedPrimitive: "null pointer dereference",
  },
  { fixture: "protocol-wraparound-negative", shouldFind: false },
  {
    fixture: "sentinel-slice-positive",
    shouldFind: true,
    expectedPrimitive: "out-of-bounds write",
  },
  { fixture: "sentinel-slice-negative", shouldFind: false },
  { fixture: "rpc-stack-positive", shouldFind: true, expectedPrimitive: "stack buffer overflow" },
  { fixture: "rpc-stack-negative", shouldFind: false },
  { fixture: "rust-guest-positive", shouldFind: true, expectedPrimitive: "out-of-bounds write" },
  { fixture: "rust-guest-negative", shouldFind: false },
  {
    fixture: "resource-provenance-positive",
    shouldFind: true,
    expectedPrimitive: "page-cache-backed write",
  },
  { fixture: "resource-provenance-negative-copy", shouldFind: false },
  { fixture: "resource-provenance-negative-validated", shouldFind: false },
];

describe("systems-hunt replay fixtures", () => {
  for (const replayCase of CASES) {
    it(`replays ${replayCase.fixture}`, { timeout: 20_000 }, async () => {
      const repoRoot = stageFixtureRepo(replayCase.fixture);
      try {
        const runtime = makeReplayRuntime();
        const baseContextOutput = await gatherContextForRoot(repoRoot);
        const config = structuredClone(DEFAULTS);
        config.taskConfig["systems-hunt"] = {
          ...config.taskConfig["systems-hunt"],
          maxSurfaces: 4,
          surfacePackDepth: 4,
          maxTriggerHypothesesPerSurface: 2,
          minLensAgreement: 2,
          enableCounterexamplePass: true,
        };

        const baseContext = makeDagRunContext(
          repoRoot,
          path.basename(path.dirname(repoRoot)),
          runtime,
          config,
        );
        const systemsContext = await systemsContextGathererTask.run({} as never, {
          ...baseContext,
          upstreamOutputs: new Map([["context-gatherer", baseContextOutput]]),
        });
        const invariantOutput = await systemsInvariantExtractTask.run({} as never, {
          ...baseContext,
          upstreamOutputs: new Map([
            ["context-gatherer", baseContextOutput],
            ["systems-context-gatherer", systemsContext],
          ]),
        });
        const triggerOutput = await systemsTriggerSynthTask.run({} as never, {
          ...baseContext,
          upstreamOutputs: new Map([
            ["context-gatherer", baseContextOutput],
            ["systems-context-gatherer", systemsContext],
            ["systems-invariant-extract", invariantOutput],
          ]),
        });
        const findings = await systemsHuntTask.run({} as never, {
          ...baseContext,
          upstreamOutputs: new Map([
            ["context-gatherer", baseContextOutput],
            ["systems-context-gatherer", systemsContext],
            ["systems-invariant-extract", invariantOutput],
            ["systems-trigger-synth", triggerOutput],
          ]),
        });

        if (replayCase.shouldFind) {
          expect(findings.length).toBeGreaterThan(0);
          const finding = findings[0]!;
          expect(finding.severity).toBe("ERROR");
          expect(finding.evidence).toContain("Trigger:");
          const artifactPath = extractSystemsHuntArtifactPath(finding);
          expect(artifactPath).toBeTruthy();
          const artifact = JSON.parse(readFileSync(path.join(repoRoot, artifactPath!), "utf-8"));
          expect(artifact.triggerSequence.length).toBeGreaterThan(0);
          expect(artifact.violatedInvariant).toBeTruthy();
          expect(artifact.memoryPrimitive).toBe(replayCase.expectedPrimitive);
          expect(artifact.corroborationStatus).toBe("survived");
        } else {
          expect(findings.filter((finding) => finding.severity === "ERROR")).toEqual([]);
        }
      } finally {
        rmSync(repoRoot, { recursive: true, force: true });
      }
    });
  }
});

function stageFixtureRepo(fixtureName: string): string {
  const fixtureRoot = path.join(FIXTURE_ROOT, fixtureName);
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), `systems-hunt-${fixtureName}-`));
  cpSync(fixtureRoot, tempRoot, { recursive: true });
  return tempRoot;
}

function makeDagRunContext(
  repoRoot: string,
  repoName: string,
  runtime: AgentRuntime,
  config = structuredClone(DEFAULTS),
): DagRunContext {
  return {
    runId: "systems-replay",
    repoRoot,
    repoName,
    config,
    runtime,
    bus: {} as never,
    upstreamOutputs: new Map(),
  };
}

function stream(messages: AgentMessage[]): AsyncIterable<AgentMessage> {
  return (async function* () {
    for (const message of messages) {
      yield message;
    }
  })();
}

function makeReplayRuntime(): AgentRuntime {
  return {
    id: "systems-replay-runtime",
    query(request: AgentQueryRequest) {
      return stream([buildResultMessage(request)]);
    },
  };
}

function buildResultMessage(request: AgentQueryRequest): AgentMessage {
  const prompt = request.prompt;
  if (prompt.startsWith("You are extracting security invariants")) {
    return {
      type: "result",
      subtype: "success",
      result: "ok",
      structuredOutput: { invariants: buildInvariantOutputs(prompt) },
      totalCostUsd: 0.1,
    };
  }
  if (prompt.startsWith("You are synthesizing explicit trigger hypotheses")) {
    return {
      type: "result",
      subtype: "success",
      result: "ok",
      structuredOutput: { triggers: buildTriggerOutputs(prompt) },
      totalCostUsd: 0.1,
    };
  }
  if (prompt.startsWith("You are running the counterexample/corroboration pass")) {
    return {
      type: "result",
      subtype: "success",
      result: "ok",
      structuredOutput: buildCorroborationOutput(prompt, request.options.cwd),
      totalCostUsd: 0.12,
    };
  }
  if (prompt.startsWith("You are running the")) {
    return {
      type: "result",
      subtype: "success",
      result: "ok",
      structuredOutput: { findings: buildLensFindings(prompt) },
      totalCostUsd: 0.15,
    };
  }
  throw new Error(`Unexpected systems replay prompt: ${prompt.slice(0, 80)}`);
}

function buildInvariantOutputs(prompt: string): object[] {
  return parseSurfaceEntries(prompt).map(({ surfaceId, filePath }) => {
    const kind = classifyFixture(filePath);
    return {
      id: `inv-${surfaceId}`,
      surfaceId,
      kind: invariantKindFor(kind),
      summary: invariantSummaryFor(kind),
      statement: invariantStatementFor(kind),
      rationale: `Replay invariant for ${kind}`,
      evidence: [`${filePath}`],
      attackerControlledFields: attackerFieldsFor(kind),
      cheapVerifiable: kind === "sentinel-slice" || kind === "rust-guest",
    };
  });
}

function buildTriggerOutputs(prompt: string): object[] {
  return parseSurfaceEntries(prompt).map(({ surfaceId, filePath }) => {
    const kind = classifyFixture(filePath);
    return {
      id: `trig-${surfaceId}`,
      surfaceId,
      orderedSteps: triggerStepsFor(kind),
      boundaryAssignments: boundaryAssignmentsFor(kind),
      statePreconditions: statePreconditionsFor(kind),
      attackerControlledFields: attackerFieldsFor(kind),
      expectedPrimitive: primitiveFor(kind),
      cheapVerifiable: kind === "sentinel-slice" || kind === "rust-guest",
      rationale: `Replay trigger for ${kind}`,
    };
  });
}

function buildLensFindings(prompt: string): object[] {
  const location = parseLocation(prompt);
  const lens = parseLens(prompt);
  const triggerIds = parseTriggerIds(prompt);
  const kind = classifyFixture(location.filePath);
  const enabledLenses = lensesFor(kind);
  if (!enabledLenses.includes(lens)) {
    return [];
  }

  return [
    {
      title: titleFor(kind),
      cwe: cweFor(kind),
      severity: "ERROR",
      confidence: lens === enabledLenses[0] ? "HIGH" : "MEDIUM",
      filePath: location.filePath,
      startLine: location.startLine,
      message: messageFor(kind),
      rationale: `${lens} corroborates ${kind}`,
      triggerHypothesisIds: triggerIds.slice(0, 1),
      violatedInvariantIds: [`inv-${location.surfaceId}`],
      violatedInvariant: invariantSummaryFor(kind),
      triggerSequence: triggerStepsFor(kind),
      attackerControlledFields: attackerFieldsFor(kind),
      memoryPrimitive: primitiveFor(kind),
      hardeningNotes: guardedPrompt(prompt)
        ? ["Guard present near sink"]
        : ["No effective guard found before primitive"],
      cheapVerifiable: kind === "sentinel-slice" || kind === "rust-guest",
      analysisPath: [{ filePath: location.filePath, line: location.startLine, role: "sink" }],
    },
  ];
}

function buildCorroborationOutput(prompt: string, cwd: string): object {
  if (guardedPrompt(prompt, cwd)) {
    return {
      status: "counterexample-found",
      rationale: "A real guard or cap blocks the trigger sequence before the primitive.",
      coherentTrigger: true,
      cheapVerifiable: false,
      guardLocations: [guardLocationForPrompt(prompt)],
      counterexampleNotes: ["Guarded negative fixture blocks the primitive."],
    };
  }

  return {
    status: "survived",
    rationale: "No effective guard or hardening blocks the replay trigger sequence.",
    coherentTrigger: true,
    cheapVerifiable: !/tcp_sack|rpcsec_gss/.test(prompt),
    guardLocations: [],
    counterexampleNotes: [],
  };
}

function parseSurfaceEntries(prompt: string): Array<{ surfaceId: string; filePath: string }> {
  const matches = [...prompt.matchAll(/surfaceId:\s*(.+?)\n[\s\S]*?Location:\s+(.+?):\d+/g)];
  return matches.map((match) => ({
    surfaceId: match[1]!.trim(),
    filePath: match[2]!.trim(),
  }));
}

function parseLocation(prompt: string): { surfaceId: string; filePath: string; startLine: number } {
  const surfaceId = prompt.match(/surfaceId:\s*(.+)/)?.[1]?.trim() ?? "surface-unknown";
  const location = prompt.match(/Location:\s+(.+?):(\d+)/);
  return {
    surfaceId,
    filePath: location?.[1]?.trim() ?? "unknown",
    startLine: Number(location?.[2] ?? 1),
  };
}

function parseLens(prompt: string): string {
  return prompt.match(/running the ([a-z-]+) lens/)?.[1]?.trim() ?? "unknown";
}

function parseTriggerIds(prompt: string): string[] {
  return [...prompt.matchAll(/\[([^\]]+)\]\s+Steps:/g)].map((match) => match[1]!.trim());
}

type ReplayFixtureKind =
  | "protocol-wraparound"
  | "sentinel-slice"
  | "rpc-stack"
  | "rust-guest"
  | "resource-provenance";

function classifyFixture(filePath: string): ReplayFixtureKind {
  if (/algif|resource_provenance|resource-provenance/i.test(filePath)) {
    return "resource-provenance";
  }
  if (/tcp_sack/i.test(filePath)) return "protocol-wraparound";
  if (/h264_slice/i.test(filePath)) return "sentinel-slice";
  if (/rpcsec_gss/i.test(filePath)) return "rpc-stack";
  return "rust-guest";
}

function invariantKindFor(kind: ReplayFixtureKind): string {
  switch (kind) {
    case "protocol-wraparound":
      return "packet-ordering";
    case "sentinel-slice":
      return "sentinel-boundary";
    case "rpc-stack":
      return "length-buffer-coupling";
    case "rust-guest":
      return "unsafe-precondition";
    case "resource-provenance":
      return "resource-provenance";
  }
}

function invariantSummaryFor(kind: ReplayFixtureKind): string {
  switch (kind) {
    case "protocol-wraparound":
      return "SACK state must remain initialized across crafted option ordering";
    case "sentinel-slice":
      return "slice_count must never collide with reserved sentinel values before indexing";
    case "rpc-stack":
      return "stack buffer capacity must dominate RPC token length";
    case "rust-guest":
      return "guest_len must be validated before entering unsafe slice construction";
    case "resource-provenance":
      return "shared backing page must not become writable scratch output";
  }
}

function invariantStatementFor(kind: ReplayFixtureKind): string {
  switch (kind) {
    case "protocol-wraparound":
      return "state != NULL before SACK option dereference";
    case "sentinel-slice":
      return "slice_count < array_len and slice_count != 0xffff";
    case "rpc-stack":
      return "len <= sizeof(stack_buf)";
    case "rust-guest":
      return "guest_len <= mapped region length";
    case "resource-provenance":
      return "shared/page-cache-backed source must be copied or isolated before writable in-place crypto output";
  }
}

function attackerFieldsFor(kind: ReplayFixtureKind): string[] {
  switch (kind) {
    case "protocol-wraparound":
      return ["seq", "ack", "len"];
    case "sentinel-slice":
      return ["slice_count"];
    case "rpc-stack":
      return ["len", "token"];
    case "rust-guest":
      return ["guest_len"];
    case "resource-provenance":
      return ["src", "dst", "page", "assoclen", "cryptlen", "authsize"];
  }
}

function triggerStepsFor(kind: ReplayFixtureKind): string[] {
  switch (kind) {
    case "protocol-wraparound":
      return ["Send initial packet", "Send crafted SACK option"];
    case "sentinel-slice":
      return ["Decode frame header", "Send 0xffff slice count"];
    case "rpc-stack":
      return ["Start RPC auth exchange", "Send oversized token"];
    case "rust-guest":
      return ["Map guest memory", "Provide oversized descriptor"];
    case "resource-provenance":
      return [
        "Import page-cache page through zero-copy path",
        "Alias source and destination scatterlists",
        "Run in-place authenticated transform",
        "Fail validation after scratch write",
      ];
  }
}

function statePreconditionsFor(kind: ReplayFixtureKind): string[] {
  switch (kind) {
    case "protocol-wraparound":
      return ["connection state allocated but stale"];
    case "sentinel-slice":
      return ["frame accepted before slice cap check"];
    case "rpc-stack":
      return ["auth token copied before cap check"];
    case "rust-guest":
      return ["descriptor accepted before guest_len validation"];
    case "resource-provenance":
      return ["shared backing page is chained into writable output before validation"];
  }
}

function boundaryAssignmentsFor(kind: ReplayFixtureKind): Record<string, string> {
  switch (kind) {
    case "protocol-wraparound":
      return { ack: "0xffff", seq: "-1 wrapped against unsigned ack" };
    case "sentinel-slice":
      return { slice_count: "0xffff" };
    case "rpc-stack":
      return { len: "64 > stack_buf[32]" };
    case "rust-guest":
      return { guest_len: "0xffff" };
    case "resource-provenance":
      return { authsize: "4-byte tag scratch", dst: "aliases source scatterlist" };
  }
}

function primitiveFor(kind: ReplayFixtureKind): string {
  switch (kind) {
    case "protocol-wraparound":
      return "null pointer dereference";
    case "sentinel-slice":
      return "out-of-bounds write";
    case "rpc-stack":
      return "stack buffer overflow";
    case "rust-guest":
      return "out-of-bounds write";
    case "resource-provenance":
      return "page-cache-backed write";
  }
}

function cweFor(kind: ReplayFixtureKind): string {
  switch (kind) {
    case "protocol-wraparound":
      return "CWE-476";
    case "sentinel-slice":
      return "CWE-787";
    case "rpc-stack":
      return "CWE-121";
    case "rust-guest":
      return "CWE-787";
    case "resource-provenance":
      return "CWE-668";
  }
}

function titleFor(kind: ReplayFixtureKind): string {
  switch (kind) {
    case "protocol-wraparound":
      return "Crafted SACK ordering reaches null state dereference";
    case "sentinel-slice":
      return "Sentinel slice count drives out-of-bounds write";
    case "rpc-stack":
      return "RPC auth token length overruns stack buffer";
    case "rust-guest":
      return "Guest length corrupts host memory through unsafe slice";
    case "resource-provenance":
      return "Zero-copy AF_ALG alias writes scratch data into shared backing page";
  }
}

function messageFor(kind: ReplayFixtureKind): string {
  switch (kind) {
    case "protocol-wraparound":
      return "Semantic packet ordering reaches a null state dereference in SACK handling";
    case "sentinel-slice":
      return "Sentinel collision lets slice_count index past the frame slice array";
    case "rpc-stack":
      return "RPC token length reaches memcpy into a fixed-size stack buffer";
    case "rust-guest":
      return "Unchecked guest_len reaches unsafe slice construction and host memory write";
    case "resource-provenance":
      return "Shared page-cache source aliases writable AF_ALG output and is mutated before auth failure";
  }
}

function lensesFor(kind: ReplayFixtureKind): string[] {
  switch (kind) {
    case "protocol-wraparound":
      return ["protocol-state", "arithmetic-sentinel"];
    case "sentinel-slice":
      return ["arithmetic-sentinel", "buffer-unsafe"];
    case "rpc-stack":
      return ["protocol-state", "buffer-unsafe"];
    case "rust-guest":
      return ["buffer-unsafe", "arithmetic-sentinel"];
    case "resource-provenance":
      return ["resource-provenance", "buffer-unsafe"];
  }
}

function guardedPrompt(prompt: string, cwd = ""): boolean {
  return (
    /negative/.test(cwd) ||
    /guarded|if\s*\(!state\)|>=\s*1024|sizeof\(stack_buf\)|guest_len\s*>\s*4096/.test(prompt)
  );
}

function guardLocationForPrompt(prompt: string): {
  filePath: string;
  line: number;
  role: string;
  snippet: string;
} {
  const location = parseLocation(prompt);
  if (/tcp_sack_guarded/.test(prompt)) {
    return {
      filePath: location.filePath,
      line: 6,
      role: "null-guard",
      snippet: "if (!state) { return -1; }",
    };
  }
  if (/h264_slice_guarded/.test(prompt)) {
    return {
      filePath: location.filePath,
      line: 6,
      role: "slice-cap",
      snippet: "if (slice_count >= 1024 || slice_count == 0xFFFF) { return -1; }",
    };
  }
  if (/rpcsec_gss_guarded/.test(prompt)) {
    return {
      filePath: location.filePath,
      line: 3,
      role: "length-cap",
      snippet: "if (len > sizeof(stack_buf)) { return -1; }",
    };
  }
  if (/algif_aead_copy/.test(prompt)) {
    return {
      filePath: location.filePath,
      line: 19,
      role: "private-copy",
      snippet: "req->dst = &private_dst;",
    };
  }
  if (/algif_aead_validated/.test(prompt)) {
    return {
      filePath: location.filePath,
      line: 19,
      role: "alias-guard",
      snippet: "if (req->src == req->dst) { return -22; }",
    };
  }
  return {
    filePath: location.filePath,
    line: 7,
    role: "guest-len-cap",
    snippet: "if desc.guest_len > 4096 { return; }",
  };
}

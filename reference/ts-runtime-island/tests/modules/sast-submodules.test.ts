import { describe, expect, it } from "vitest";
import { createAgenticSastModule } from "../../src/modules/agentic-sast/agentic-sast.js";
import { createCarliniThreatHuntModule } from "../../src/modules/carlini-threat-hunt/carlini-threat-hunt.js";
import { createCodeqlModule } from "../../src/modules/codeql/codeql.js";
import { createContextModule } from "../../src/modules/context/context.js";
import { createFindingsModule } from "../../src/modules/findings/findings.js";
import { createPatchModule } from "../../src/modules/patch/patch.js";
import { createSemgrepModule } from "../../src/modules/semgrep/semgrep.js";
import { createTaintIrisModule } from "../../src/modules/taint-iris/taint-iris.js";
import { createTaintIrisNextModule } from "../../src/modules/taint-iris-next/taint-iris-next.js";
import { createTriageModule } from "../../src/modules/triage/triage.js";
import { createVerifyModule } from "../../src/modules/verify/verify.js";

describe("SAST sub-modules", () => {
  const cases = [
    { factory: createSemgrepModule, id: "semgrep", tool: "semgrep:scan", rank: "great" },
    { factory: createCodeqlModule, id: "codeql", tool: "codeql:scan", rank: "excellent" },
    {
      factory: createAgenticSastModule,
      id: "agentic-sast",
      tool: "agentic-sast:scan",
      rank: "good",
    },
    {
      factory: createCarliniThreatHuntModule,
      id: "carlini-threat-hunt",
      tool: "carlini-threat-hunt:run",
      rank: "good",
    },
    { factory: createTaintIrisModule, id: "taint-iris", tool: "taint-iris:hunt", rank: "good" },
    {
      factory: createTaintIrisNextModule,
      id: "taint-iris-next",
      tool: "taint-iris-next:hunt",
      rank: "normal",
    },
    { factory: createTriageModule, id: "triage", tool: "triage:run", rank: "good" },
    { factory: createVerifyModule, id: "verify", tool: "verify:finding", rank: "good" },
    { factory: createPatchModule, id: "patch", tool: "patch:finding", rank: "normal" },
    { factory: createFindingsModule, id: "findings", tool: "findings:list", rank: "great" },
    { factory: createContextModule, id: "context", tool: "context:build", rank: "excellent" },
  ];

  for (const { factory, id, tool, rank } of cases) {
    it(`${id} has expected shape and primary tool`, () => {
      const mod = factory();
      expect(mod.id).toBe(id);
      expect(mod.version).toBe("0.17.2");
      expect(mod.rank).toBe(rank);
      expect(mod.tools.map((t) => t.name)).toContain(tool);
      for (const t of mod.tools) {
        expect(t.headless).toBe(true);
      }
    });
  }

  it("agentic-sast / taint-iris / carlini-threat-hunt declare context snapshot requirements", () => {
    const reqs = (mod: ReturnType<typeof createAgenticSastModule>) =>
      (mod.requires ?? []).filter((r) => r.kind === "snapshot");
    expect(reqs(createAgenticSastModule()).map((r) => r.kind === "snapshot" && r.field)).toEqual([
      "appModel",
    ]);
    expect(reqs(createTaintIrisModule()).map((r) => r.kind === "snapshot" && r.field)).toEqual([
      "appModel",
    ]);
    expect(reqs(createTaintIrisNextModule()).map((r) => r.kind === "snapshot" && r.field)).toEqual([
      "appModel",
    ]);
    const hunt = reqs(createCarliniThreatHuntModule()).map((r) => r.kind === "snapshot" && r.field);
    expect(hunt).toContain("appModel");
    expect(hunt).toContain("threatModel");
    const huntModules = reqs(createCarliniThreatHuntModule()).map(
      (r) => r.kind === "snapshot" && r.moduleId,
    );
    expect(huntModules).toContain("context");
    expect(huntModules).toContain("threat-model");
  });

  it("taint-iris hunt declares checkpoint resume and live pause-resume", () => {
    const tool = createTaintIrisModule().tools.find((t) => t.name === "taint-iris:hunt");
    expect(tool?.runLifecycle).toEqual({
      persistence: "pipeline-checkpoint",
      resume: "checkpoint",
      liveControl: "pause-resume",
      pipelineTasks: ["taint-iris:hunt"],
      pipelineContext: "none",
    });
    expect(tool?.inputSchema.properties?.resume).toEqual({
      type: ["boolean", "string"],
      description: "Resume the latest checkpoint or a specific run id.",
    });
  });

  it("triage / verify / patch declare findings requirement", () => {
    for (const factory of [createTriageModule, createVerifyModule, createPatchModule]) {
      const mod = factory();
      const findingsReq = (mod.requires ?? []).find((r) => r.kind === "findings");
      expect(findingsReq).toBeDefined();
    }
  });

  it("context / semgrep / codeql / findings have no requires (standalone)", () => {
    for (const factory of [
      createContextModule,
      createSemgrepModule,
      createCodeqlModule,
      createFindingsModule,
    ]) {
      const mod = factory();
      expect(mod.requires ?? []).toEqual([]);
    }
  });
});

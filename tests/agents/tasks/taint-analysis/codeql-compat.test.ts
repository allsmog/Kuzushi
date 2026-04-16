import { describe, expect, it, vi } from "vitest";
import {
  __taintAnalysisCodeqlCompatInternals,
  CodeqlProfileDetectionError,
  candidateProfiles,
  detectWorkingProfile,
  formatProfileDiagnostics,
  profileById,
} from "../../../../src/agents/tasks/taint-analysis/codeql-compat.js";

describe("taint-analysis-codeql-compat", () => {
  it("returns candidate profiles in deterministic order per language", () => {
    expect(candidateProfiles("go").map((profile) => profile.id)).toEqual([
      "go-dataflow",
      "go-dataflow-new",
    ]);
    expect(candidateProfiles("python").map((profile) => profile.id)).toEqual([
      "python-dataflow-new",
      "python-dataflow-old",
    ]);
    expect(candidateProfiles("java").map((profile) => profile.id)).toEqual([
      "java-dataflow",
      "java-dataflow-new",
    ]);
    expect(candidateProfiles("javascript").map((profile) => profile.id)).toEqual([
      "javascript-dataflow",
      "javascript-dataflow-new",
    ]);
    expect(candidateProfiles("csharp").map((profile) => profile.id)).toEqual([
      "csharp-dataflow",
      "csharp-dataflow-new",
    ]);
  });

  it("fails manual override validation for unknown profile ids", async () => {
    await expect(
      detectWorkingProfile({
        language: "go",
        codeqlBinary: "codeql",
        workspaceDir: "/tmp/workspace",
        codeqlApiProfile: "go-nonexistent",
        validate: async () => undefined,
      }),
    ).rejects.toThrow("Valid profiles");
  });

  it("manual override validates only the requested profile", async () => {
    const validate = vi.fn(async () => undefined);
    const result = await detectWorkingProfile({
      language: "go",
      codeqlBinary: "codeql",
      workspaceDir: "/tmp/workspace",
      codeqlApiProfile: "go-dataflow-new",
      codeqlProfileFallbacks: true,
      validate,
    });

    expect(validate).toHaveBeenCalledTimes(1);
    expect(result.selected.id).toBe("go-dataflow-new");
    expect(result.tried).toEqual([{ id: "go-dataflow-new", ok: true }]);
  });

  it("formats aggregated diagnostics with attempted profile errors", () => {
    const diagnostics = formatProfileDiagnostics({
      language: "go",
      codeqlVersion: "CodeQL CLI 2.20.7",
      requestedProfile: "auto",
      fallbackEnabled: true,
      compatRecordPath: "/tmp/iris/exploration/codeql_compat.json",
      tried: [
        { id: "go-dataflow", ok: false, error: "module missing" },
        { id: "go-dataflow-new", ok: false, error: "predicate mismatch" },
      ],
    });

    expect(diagnostics).toContain("CodeQL version: CodeQL CLI 2.20.7");
    expect(diagnostics).toContain("Requested profile: auto");
    expect(diagnostics).toContain("go-dataflow: failed");
    expect(diagnostics).toContain("/tmp/iris/exploration/codeql_compat.json");
  });

  it("renders probe queries with profile-specific imports", () => {
    const profile = profileById("go", "go-dataflow");
    expect(profile).not.toBeNull();
    if (!profile) {
      return;
    }

    const probe = __taintAnalysisCodeqlCompatInternals.renderProbeQuery(profile);
    expect(probe).toContain("import go");
    expect(probe).toContain("import semmle.go.dataflow.DataFlow");
    expect(probe).toContain("import semmle.go.dataflow.TaintTracking");
  });

  it("returns tried profile diagnostics on detection failure", async () => {
    await expect(
      detectWorkingProfile({
        language: "go",
        codeqlBinary: "codeql",
        workspaceDir: "/tmp/workspace",
        codeqlApiProfile: "auto",
        validate: async (profile) => {
          throw new Error(`${profile.id} failed`);
        },
      }),
    ).rejects.toMatchObject({
      name: "CodeqlProfileDetectionError",
    });

    try {
      await detectWorkingProfile({
        language: "go",
        codeqlBinary: "codeql",
        workspaceDir: "/tmp/workspace",
        codeqlApiProfile: "auto",
        validate: async (profile) => {
          throw new Error(`${profile.id} failed`);
        },
      });
      expect.unreachable("expected detectWorkingProfile to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(CodeqlProfileDetectionError);
      const detectionError = error as CodeqlProfileDetectionError;
      expect(detectionError.tried).toHaveLength(2);
      expect(detectionError.tried[0]?.id).toBe("go-dataflow");
      expect(detectionError.tried[1]?.id).toBe("go-dataflow-new");
    }
  });
});

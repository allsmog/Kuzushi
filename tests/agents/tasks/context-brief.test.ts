import { describe, expect, it } from "vitest";
import { __contextClassifierInternals } from "../../../src/agents/tasks/context-brief.js";
import type { FileIndex, RepoContext, TargetBrief } from "../../../src/types.js";

const { buildClassifierPrompt, buildDeterministicTargetBrief, normalizeTargetBrief } =
  __contextClassifierInternals;

function fileIndex(paths: string[]): FileIndex {
  return {
    tree: paths.map((path) => ({ path })),
    totalFiles: paths.length,
    truncated: false,
    patternMatches: {},
  };
}

function repoContext(overrides: Partial<RepoContext> = {}): RepoContext {
  return {
    languages: [],
    frameworks: [],
    authPatterns: [],
    sanitizationLibs: [],
    ormOrDb: [],
    entryPoints: [],
    ...overrides,
  };
}

describe("context classifier target brief", () => {
  it("classifies a .github target as CI/CD automation with concrete evidence", () => {
    const brief = buildDeterministicTargetBrief(
      "/tmp/repo/.github",
      repoContext(),
      fileIndex(["workflows/release.yml", "actions/setup/action.yml", "scripts/publish.sh"]),
    );

    expect(brief.targetKind).toBe("ci-cd automation");
    expect(brief.platformHints).toContain("github-actions");
    expect(brief.domainLanguage).toEqual(
      expect.arrayContaining(["workflows", "jobs", "runners", "secrets"]),
    );
    expect(brief.evidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ signal: "github-workflows", filePath: "workflows/release.yml" }),
        expect.objectContaining({ signal: "github-actions", filePath: "actions/setup/action.yml" }),
        expect.objectContaining({ signal: "scripts", filePath: "scripts/publish.sh" }),
      ]),
    );
    expect(brief.avoidAssumptions.join(" ")).not.toMatch(/\bORM\b|middleware/i);
  });

  it("classifies Buildkite and Jenkins as CI/CD automation", () => {
    const buildkite = buildDeterministicTargetBrief(
      "/tmp/repo",
      repoContext(),
      fileIndex([".buildkite/pipeline.yml"]),
    );
    const jenkins = buildDeterministicTargetBrief(
      "/tmp/repo",
      repoContext(),
      fileIndex(["Jenkinsfile"]),
    );

    expect(buildkite.targetKind).toBe("ci-cd automation");
    expect(buildkite.platformHints).toContain("buildkite");
    expect(jenkins.targetKind).toBe("ci-cd automation");
    expect(jenkins.platformHints).toContain("jenkins");
  });

  it("classifies Terraform and Kubernetes as infrastructure configuration", () => {
    const terraform = buildDeterministicTargetBrief(
      "/tmp/infra",
      repoContext(),
      fileIndex(["main.tf", "variables.tf"]),
    );
    const kubernetes = buildDeterministicTargetBrief(
      "/tmp/k8s",
      repoContext(),
      fileIndex(["k8s/deployment.yaml", "helm/Chart.yaml"]),
    );

    expect(terraform.targetKind).toBe("infrastructure configuration");
    expect(terraform.platformHints).toContain("terraform");
    expect(kubernetes.targetKind).toBe("infrastructure configuration");
    expect(kubernetes.platformHints).toContain("kubernetes");
  });

  it("classifies framework-backed services as application services", () => {
    const brief = buildDeterministicTargetBrief(
      "/tmp/web",
      repoContext({
        frameworks: ["Express"],
        entryPoints: ["src/routes/users.ts"],
      }),
      fileIndex(["src/routes/users.ts"]),
    );

    expect(brief.targetKind).toBe("application service");
    expect(brief.domainLanguage).toContain("routes");
    expect(brief.entrypointConcepts).toContain("HTTP routes");
  });

  it("builds a classifier prompt from deterministic facts and operator guidance", () => {
    const fallback = buildDeterministicTargetBrief(
      "/tmp/repo/.github",
      repoContext(),
      fileIndex(["workflows/ci.yml"]),
    );
    const prompt = buildClassifierPrompt({
      target: "/tmp/repo/.github",
      deterministicFallback: fallback,
      repoContext: repoContext(),
      fileIndex: fileIndex(["workflows/ci.yml"]),
      guidance: "Prefer CI/CD vocabulary.",
    });

    expect(prompt).toContain("Classify the security analysis lens");
    expect(prompt).toContain("ci-cd automation");
    expect(prompt).toContain("Operator guidance");
    expect(prompt).toContain("Prefer CI/CD vocabulary.");
  });

  it("normalizes strict-schema output with fallback values for empty arrays", () => {
    const fallback: TargetBrief = buildDeterministicTargetBrief(
      "/tmp/repo",
      repoContext(),
      fileIndex(["main.tf"]),
    );
    const normalized = normalizeTargetBrief(
      {
        targetKind: "deployment configuration",
        confidence: 1.2,
        platformHints: [],
        domainLanguage: [],
        entrypointConcepts: [],
        executionSurfaceConcepts: [],
        trustBoundaryConcepts: [],
        assetConcepts: [],
        threatLenses: [],
        avoidAssumptions: ["avoid web assumptions"],
        evidence: [],
      },
      fallback,
    );

    expect(normalized?.targetKind).toBe("deployment configuration");
    expect(normalized?.confidence).toBe(1);
    expect(normalized?.platformHints).toEqual(fallback.platformHints);
    expect(normalized?.source).toBe("llm");
  });
});

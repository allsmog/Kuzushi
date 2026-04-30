import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type {
  AgentMessage,
  AgentQueryRequest,
  AgentRuntime,
} from "../../src/agent-runtime/types.js";
import type { ThreatModelDocument } from "../../src/agents/tasks/threat-modeling/types.js";
import {
  buildTaintIrisNextAgentPrompt,
  runTaintIrisNextAgent,
} from "../../src/modules/taint-iris-next/agent.js";
import {
  buildStructuralQueriesFromCatalog,
  filterCatalogForContext,
  rankCatalogEntries,
  renderCatalogForPrompt,
  TAINT_IRIS_NEXT_CWE_CATALOG,
  validateAgentCweSelections,
} from "../../src/modules/taint-iris-next/cwe-reference.js";
import {
  linkTaintCandidates,
  rankLinkedStoriesForReview,
} from "../../src/modules/taint-iris-next/evidence-tools.js";
import {
  astGrepJsonToStructuralMatches,
  buildAstGrepPatternsForQuery,
  buildCodeqlCatalogQueries,
  buildCodeqlCatalogQuery,
  codeqlFindingsToEvidence,
  runStructuralExtractor,
} from "../../src/modules/taint-iris-next/extractors.js";
import {
  buildTaintIrisNextPlan,
  chooseBackend,
  resolveTaintIrisNextPersistentArtifacts,
} from "../../src/modules/taint-iris-next/planner.js";
import { createTaintIrisNextModule } from "../../src/modules/taint-iris-next/taint-iris-next.js";
import type {
  TaintIrisNextCandidate,
  TaintIrisNextEvidenceResult,
  TaintIrisNextLinkedStory,
} from "../../src/modules/taint-iris-next/types.js";
import type { Finding } from "../../src/scanners/types.js";
import {
  createFakeRuntime,
  createMockToolContext,
  getRecordedActivity,
} from "../../src/testing/index.js";
import type { RepoContext } from "../../src/types.js";

const REQUIRED_CWES = [
  "CWE-22",
  "CWE-73",
  "CWE-77",
  "CWE-78",
  "CWE-79",
  "CWE-89",
  "CWE-90",
  "CWE-94",
  "CWE-95",
  "CWE-113",
  "CWE-117",
  "CWE-190",
  "CWE-200",
  "CWE-287",
  "CWE-326",
  "CWE-327",
  "CWE-346",
  "CWE-352",
  "CWE-362",
  "CWE-367",
  "CWE-400",
  "CWE-434",
  "CWE-502",
  "CWE-601",
  "CWE-611",
  "CWE-639",
  "CWE-776",
  "CWE-798",
  "CWE-829",
  "CWE-862",
  "CWE-863",
  "CWE-915",
  "CWE-918",
  "CWE-943",
  "CWE-1321",
  "CWE-1333",
  "CWE-1336",
];

function repoContext(partial: Partial<RepoContext>): RepoContext {
  return {
    languages: [],
    frameworks: [],
    authPatterns: [],
    sanitizationLibs: [],
    ormOrDb: [],
    entryPoints: [],
    ...partial,
  };
}

function threatModel(cwes: string[]): ThreatModelDocument {
  return {
    version: "1",
    dfd: { nodes: [], flows: [], trustBoundaries: [] },
    threats: [
      {
        id: "T-1",
        actorIds: [],
        entrypointIds: [],
        targetElementIds: [],
        flowIds: [],
        category: "tampering",
        title: "Webhook URL can trigger internal metadata fetch",
        description: "User-controlled webhook callback URLs may reach internal services.",
        attackVector: "Submit a callback URL that points at a cloud metadata endpoint.",
        preconditions: ["attacker controls callback URL"],
        impact: "high",
        likelihood: "medium",
        existingMitigations: [],
        missingMitigations: ["URL allowlist"],
        relatedCwe: cwes,
        affectedFiles: [],
      },
    ],
    summary: {
      total: 1,
      bySeverity: { high: 1 },
      byCategory: {
        spoofing: 0,
        tampering: 1,
        repudiation: 0,
        "information-disclosure": 0,
        "denial-of-service": 0,
        "elevation-of-privilege": 0,
      },
    },
  };
}

function tempRepo(): string {
  return mkdtempSync(path.join(tmpdir(), "kuzushi-iris-next-"));
}

function writePersistentContext(root: string, context: RepoContext): void {
  mkdirSync(path.join(root, ".kuzushi"), { recursive: true });
  writeFileSync(
    path.join(root, ".kuzushi", "context-snapshot.json"),
    `${JSON.stringify(
      {
        target: root,
        timestamp: Date.now(),
        discovery: "flat",
        options: { enrichment: true, threatModel: true },
        repoContext: context,
        fileIndex: { tree: [] },
        appModel: { routes: [] },
      },
      null,
      2,
    )}\n`,
  );
}

function writePersistentThreatModel(root: string, model: ThreatModelDocument): void {
  mkdirSync(path.join(root, ".kuzushi"), { recursive: true });
  writeFileSync(
    path.join(root, ".kuzushi", "threat-model.json"),
    `${JSON.stringify(model, null, 2)}\n`,
  );
}

function seededContext(root: string, context: RepoContext, model: ThreatModelDocument) {
  return createMockToolContext({
    cwd: root,
    target: root,
    seedTaskOutputs: new Map<string, unknown>([
      ["context-gatherer", { repoContext: context }],
      ["threat-model-randori", { document: model, findings: [] }],
    ]),
  });
}

function evidenceResult(
  partial: Partial<TaintIrisNextEvidenceResult>,
): TaintIrisNextEvidenceResult {
  return {
    backend: "structural",
    tool: "rg",
    evidence: [],
    candidates: [],
    linkedStories: [],
    labeledSpecs: [],
    queryCount: 0,
    candidateCounts: {},
    labeledSpecCounts: {},
    linkedStoryCount: 0,
    backendPathCount: 0,
    structuralEngine: "rg",
    triageSummary: { finding: 0, candidate: 0, rejected: 0 },
    outcome: "structural-only",
    warnings: [],
    ...partial,
  };
}

function backendRuntime(
  id: "claude" | "pi-ai" | "codex",
  responses: Parameters<typeof createFakeRuntime>[0],
) {
  return Object.assign(createFakeRuntime(responses), { id });
}

function streamedRuntime(
  id: "claude" | "pi-ai" | "codex",
  messages: AgentMessage[],
): AgentRuntime & {
  calls: AgentQueryRequest[];
} {
  const calls: AgentQueryRequest[] = [];
  return {
    id,
    calls,
    async *query(request: AgentQueryRequest): AsyncIterable<AgentMessage> {
      calls.push(request);
      for (const message of messages) yield message;
    },
  };
}

function taintCandidate(
  partial: Partial<TaintIrisNextCandidate> & {
    id: string;
    cwe: string;
    role: TaintIrisNextCandidate["role"];
    filePath: string;
    line: number;
    snippet: string;
  },
): TaintIrisNextCandidate {
  return {
    taintClass: partial.cwe === "CWE-117" ? "log-injection" : "os-command-injection",
    track: "taint",
    kind: partial.role === "sink" ? "external-arg-sink" : "internal-param-source",
    pattern: partial.role,
    language: "python",
    confidence: "medium",
    catalogSignal: `${partial.role}: ${partial.pattern ?? partial.role}`,
    source: "structural",
    ...partial,
  };
}

function linkedStory(
  partial: Partial<TaintIrisNextLinkedStory> & {
    id: string;
    cwe: string;
    taintClass: string;
    sourceCandidateId: string;
    sinkCandidateId: string;
    filePath: string;
    sourceLine: number;
    sinkLine: number;
  },
): TaintIrisNextLinkedStory {
  return {
    track: "taint",
    evidenceLevel: "linked",
    language: "python",
    sharedTokens: [],
    rationale: "line-local flow.",
    ...partial,
  };
}

describe("taint-iris-next CWE reference", () => {
  it("ships the required normalized CWE catalog without duplicate ids", () => {
    const ids = TAINT_IRIS_NEXT_CWE_CATALOG.map((entry) => entry.cwe);
    expect(new Set(ids).size).toBe(ids.length);

    for (const id of ids) {
      expect(id).toMatch(/^CWE-\d+$/u);
    }
    for (const required of REQUIRED_CWES) {
      expect(ids).toContain(required);
    }
  });

  it("filters and ranks Rust-native candidates from language context", () => {
    const context = repoContext({ languages: ["Rust"] });
    const filtered = filterCatalogForContext(context, undefined, []);
    const ranked = rankCatalogEntries(filtered, { context });

    expect(filtered.map((entry) => entry.cwe)).toContain("CWE-190");
    expect(ranked.find((entry) => entry.cwe === "CWE-190")?.reasons).toContain("language match");
  });

  it("keeps Ruby/web/database taint classes visible for Rails-style projects", () => {
    const context = repoContext({
      languages: ["Ruby"],
      frameworks: ["Rails"],
      ormOrDb: ["PostgreSQL", "ActiveRecord"],
      entryPoints: ["routes.rb"],
    });
    const ranked = rankCatalogEntries(filterCatalogForContext(context, undefined), { context });
    const top = ranked.slice(0, 12).map((entry) => entry.cwe);

    expect(top).toContain("CWE-89");
    expect(top).toContain("CWE-79");
    expect(top).toContain("CWE-601");
  });

  it("prioritizes threat-model related CWEs in mixed-language repos", () => {
    const context = repoContext({ languages: ["TypeScript", "Rust"], frameworks: ["Express"] });
    const model = threatModel(["CWE-918"]);
    const ranked = rankCatalogEntries(filterCatalogForContext(context, model), {
      context,
      threatModel: model,
    });

    expect(ranked[0]?.cwe).toBe("CWE-918");
    expect(ranked[0]?.reasons).toContain("threat-model CWE");
  });

  it("renders a bounded agent prompt catalog from ranked entries", () => {
    const context = repoContext({ languages: ["TypeScript"], frameworks: ["Express"] });
    const prompt = renderCatalogForPrompt(
      rankCatalogEntries(filterCatalogForContext(context, undefined), { context }).slice(0, 5),
    );

    expect(prompt).toContain("## CWE Candidate Catalog");
    expect(prompt).toContain("must choose CWE themes from this catalog");
    expect(prompt).toContain("sources:");
    expect(prompt).toContain("sinks:");
    expect(prompt).toMatch(/CWE-\d+/u);
  });

  it("builds structural query seeds for core taint classes", () => {
    const wanted = new Set([
      "CWE-22",
      "CWE-78",
      "CWE-79",
      "CWE-89",
      "CWE-502",
      "CWE-601",
      "CWE-611",
      "CWE-918",
    ]);
    const queries = buildStructuralQueriesFromCatalog(
      TAINT_IRIS_NEXT_CWE_CATALOG.filter((entry) => wanted.has(entry.cwe)),
    );

    for (const cwe of wanted) {
      expect(queries.some((query) => query.cwe === cwe)).toBe(true);
    }
    expect(queries.some((query) => query.cwe === "CWE-89" && query.pattern === "query")).toBe(true);
    expect(queries.some((query) => query.cwe === "CWE-918" && query.pattern === "fetch")).toBe(
      true,
    );
  });

  it("generates ast-grep structural patterns for Python, Ruby, Rust, and JS/TS", () => {
    const query = {
      id: "CWE-78:sink:exec",
      cwe: "CWE-78",
      taintClass: "command-injection",
      role: "sink" as const,
      pattern: "exec(",
      languages: ["python", "ruby", "rust", "javascript", "typescript"],
    };

    const patterns = buildAstGrepPatternsForQuery(query, []);
    expect(patterns).toEqual(
      expect.arrayContaining([
        { language: "python", pattern: "exec($$$ARGS)" },
        { language: "ruby", pattern: "exec($$$ARGS)" },
        { language: "rust", pattern: "exec($$$ARGS)" },
        { language: "javascript", pattern: "exec($$$ARGS)" },
        { language: "typescript", pattern: "exec($$$ARGS)" },
      ]),
    );
  });

  it("parses ast-grep JSON matches into structural rows", () => {
    const root = tempRepo();
    const file = path.join(root, "app.py");
    const matches = astGrepJsonToStructuralMatches(
      JSON.stringify([
        {
          text: "subprocess.run(cmd)",
          range: { start: { line: 4, column: 2 } },
          file,
          lines: "  subprocess.run(cmd)",
          language: "Python",
        },
      ]),
      root,
      "sink: subprocess [ast-grep:subprocess.run($$$ARGS)]",
    );

    expect(matches).toEqual([
      expect.objectContaining({
        filePath: "app.py",
        line: 5,
        snippet: "subprocess.run(cmd)",
        language: "python",
        callExpression: "subprocess.run(cmd)",
      }),
    ]);
  });

  it("links source and sink candidates in one file without promoting control CWEs", () => {
    const linked = linkTaintCandidates([
      {
        id: "cand-1",
        cwe: "CWE-78",
        taintClass: "command-injection",
        track: "taint",
        role: "source",
        kind: "internal-param-source",
        pattern: "request",
        filePath: "app.py",
        line: 10,
        snippet: "cmd = request.args.get('cmd')",
        language: "python",
        confidence: "medium",
        catalogSignal: "source: request",
        source: "structural",
        assignedVariable: "cmd",
      },
      {
        id: "cand-2",
        cwe: "CWE-78",
        taintClass: "command-injection",
        track: "taint",
        role: "sink",
        kind: "external-arg-sink",
        pattern: "subprocess",
        filePath: "app.py",
        line: 11,
        snippet: "subprocess.run(cmd, shell=True)",
        language: "python",
        confidence: "medium",
        catalogSignal: "sink: subprocess",
        source: "structural",
      },
      {
        id: "cand-3",
        cwe: "CWE-862",
        taintClass: "missing-authorization",
        track: "control",
        role: "source",
        kind: "control-context",
        pattern: "route",
        filePath: "app.py",
        line: 20,
        snippet: "@app.get('/admin')",
        language: "python",
        confidence: "medium",
        catalogSignal: "source: route",
        source: "structural",
      },
      {
        id: "cand-4",
        cwe: "CWE-862",
        taintClass: "missing-authorization",
        track: "control",
        role: "sink",
        kind: "control-context",
        pattern: "admin",
        filePath: "app.py",
        line: 21,
        snippet: "return admin_data()",
        language: "python",
        confidence: "medium",
        catalogSignal: "sink: admin",
        source: "structural",
      },
    ]);

    expect(linked).toHaveLength(1);
    expect(linked[0]).toEqual(
      expect.objectContaining({
        cwe: "CWE-78",
        sourceCandidateId: "cand-1",
        sinkCandidateId: "cand-2",
        sharedTokens: expect.arrayContaining(["cmd"]),
      }),
    );
  });

  it("ranks command and path stories above weak parameterized logger stories", () => {
    const candidates = [
      taintCandidate({
        id: "cmd-source",
        cwe: "CWE-78",
        role: "source",
        filePath: "exec.py",
        line: 10,
        snippet: "def run(command):",
        pattern: "command",
        catalogSignal: "source: command parameter",
      }),
      taintCandidate({
        id: "cmd-sink",
        cwe: "CWE-78",
        role: "sink",
        filePath: "exec.py",
        line: 12,
        snippet: "subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)",
        pattern: "subprocess.Popen",
        catalogSignal: "sink: subprocess shell",
      }),
      taintCandidate({
        id: "path-source",
        cwe: "CWE-22",
        role: "source",
        filePath: "files.py",
        line: 5,
        snippet: "def update(override_yml):",
        pattern: "override_yml",
        catalogSignal: "source: path parameter",
      }),
      taintCandidate({
        id: "path-sink",
        cwe: "CWE-22",
        role: "sink",
        filePath: "files.py",
        line: 7,
        snippet: "with open(override_yml, 'w') as fileoverwrite:",
        pattern: "open",
        catalogSignal: "sink: open",
      }),
      taintCandidate({
        id: "log-source",
        cwe: "CWE-117",
        role: "source",
        filePath: "server.py",
        line: 20,
        snippet: "async def _run_server(self, name: str):",
        pattern: "name",
        catalogSignal: "source: name parameter",
      }),
      taintCandidate({
        id: "log-sink-1",
        cwe: "CWE-117",
        role: "sink",
        filePath: "server.py",
        line: 30,
        snippet: "logger.info(\"Server '%s' connected\", name)",
        pattern: "logger.info",
        catalogSignal: "sink: logger",
      }),
      taintCandidate({
        id: "log-sink-2",
        cwe: "CWE-117",
        role: "sink",
        filePath: "server.py",
        line: 35,
        snippet: "logger.error(\"Server '%s' failed\", name)",
        pattern: "logger.error",
        catalogSignal: "sink: logger",
      }),
    ];
    const ranked = rankLinkedStoriesForReview(
      [
        linkedStory({
          id: "log-1",
          cwe: "CWE-117",
          taintClass: "log-injection",
          sourceCandidateId: "log-source",
          sinkCandidateId: "log-sink-1",
          filePath: "server.py",
          sourceLine: 20,
          sinkLine: 30,
          sharedTokens: ["name", "server"],
          enclosingSymbol: "_run_server",
        }),
        linkedStory({
          id: "log-2",
          cwe: "CWE-117",
          taintClass: "log-injection",
          sourceCandidateId: "log-source",
          sinkCandidateId: "log-sink-2",
          filePath: "server.py",
          sourceLine: 20,
          sinkLine: 35,
          sharedTokens: ["name", "server"],
          enclosingSymbol: "_run_server",
        }),
        linkedStory({
          id: "path-1",
          cwe: "CWE-22",
          taintClass: "path-traversal",
          sourceCandidateId: "path-source",
          sinkCandidateId: "path-sink",
          filePath: "files.py",
          sourceLine: 5,
          sinkLine: 7,
          sharedTokens: ["override_yml"],
          enclosingSymbol: "update",
        }),
        linkedStory({
          id: "cmd-1",
          cwe: "CWE-78",
          taintClass: "os-command-injection",
          sourceCandidateId: "cmd-source",
          sinkCandidateId: "cmd-sink",
          filePath: "exec.py",
          sourceLine: 10,
          sinkLine: 12,
          sharedTokens: ["command"],
          enclosingSymbol: "run",
        }),
      ],
      candidates,
    );

    expect(ranked.map((story) => story.id)).toEqual(["cmd-1", "path-1", "log-1"]);
  });

  it("synthesizes Python internal parameter sources and links them to actionable sinks", async () => {
    const root = tempRepo();
    mkdirSync(path.join(root, "app"), { recursive: true });
    writeFileSync(
      path.join(root, "app", "runner.py"),
      [
        "import subprocess",
        "",
        "def run_job(exec_cmd, container):",
        '    docker_cmd = f"docker exec {container} {exec_cmd}"',
        "    return subprocess.call(['/bin/bash', '-c', docker_cmd])",
        "",
      ].join("\n"),
    );
    const context = repoContext({ languages: ["Python"], entryPoints: ["app/runner.py"] });
    const ctx = seededContext(root, context, threatModel(["CWE-77"]));
    const plan = buildTaintIrisNextPlan(
      { target: root, maxCatalogEntries: 1, maxEvidencePerCwe: 8, maxCandidatesPerCwe: 16 },
      ctx,
    );

    const result = await runStructuralExtractor(plan, ctx);
    expect(result.linkedStoryCount).toBeGreaterThan(0);
    expect(result.linkedStories[0]).toEqual(
      expect.objectContaining({
        cwe: "CWE-77",
        filePath: "app/runner.py",
        enclosingSymbol: "run_job",
      }),
    );
    expect(
      result.evidence.some(
        (item) =>
          item.role === "source" &&
          item.pattern === "implicit-param:exec_cmd" &&
          item.evidenceLevel === "linked",
      ),
    ).toBe(true);
    expect(result.outcome).toBe("linked-evidence");
  });

  it("rejects agent-selected CWEs outside the catalog unless custom rationale is supplied", () => {
    const valid = validateAgentCweSelections([
      { cwe: "CWE-89", signalCitations: ["sink: query"] },
      { cwe: "CWE-9999", customCweRationale: "Project-specific generated-code sink." },
    ]);
    expect(valid.valid).toBe(true);
    expect(valid.accepted.map((selection) => selection.cwe)).toEqual(["CWE-89", "CWE-9999"]);

    const invalid = validateAgentCweSelections([{ cwe: "CWE-89" }, { cwe: "CWE-9999" }]);
    expect(invalid.valid).toBe(false);
    expect(invalid.rejected.map((selection) => selection.cwe)).toEqual(["CWE-89", "CWE-9999"]);
  });

  it("selects structural by default and records existing CodeQL databases without creating one", () => {
    const root = tempRepo();
    mkdirSync(path.join(root, ".kuzushi", "codeql-db"), { recursive: true });

    const auto = chooseBackend("auto", root);
    expect(auto.selected).toBe("structural");
    expect(auto.codeqlDbPath).toBe(path.join(root, ".kuzushi", "codeql-db"));
    expect(auto.corroborateWithCodeql).toBe(true);

    const explicit = chooseBackend("codeql", root);
    expect(explicit.selected).toBe("codeql");
    expect(explicit.codeqlDbPath).toBe(path.join(root, ".kuzushi", "codeql-db"));

    const missing = chooseBackend("codeql", path.join(root, "missing"));
    expect(missing.selected).toBe("structural");
    expect(missing.warnings.join(" ")).toContain("no existing CodeQL DB");
  });

  it("treats empty context artifacts as incomplete but does not hard-block on empty threat model", async () => {
    const root = tempRepo();
    writePersistentContext(root, repoContext({}));
    writePersistentThreatModel(root, {
      version: "2.0",
      dfd: { nodes: [], flows: [], trustBoundaries: [] },
      threats: [],
      summary: { total: 0, bySeverity: {}, byCategory: {} },
    } as ThreatModelDocument);
    const ctx = createMockToolContext({ cwd: root, target: root });
    const tool = createTaintIrisNextModule().tools.find(
      (candidate) => candidate.name === "taint-iris-next:hunt",
    );

    const result = await tool?.execute({ target: root, mode: "plan" }, ctx);
    expect(result?.ok).toBe(false);
    expect(result?.output).toContain("context snapshot exists but lacks");
    expect(result?.output).toContain("warning only");
  });

  it("continues with usable context when the threat model is empty", async () => {
    const root = tempRepo();
    writePersistentContext(root, repoContext({ languages: ["Python"], frameworks: ["FastAPI"] }));
    writePersistentThreatModel(root, {
      version: "2.0",
      dfd: { nodes: [], flows: [], trustBoundaries: [] },
      threats: [],
      summary: { total: 0, bySeverity: {}, byCategory: {} },
    } as ThreatModelDocument);
    mkdirSync(path.join(root, "app"), { recursive: true });
    writeFileSync(
      path.join(root, "app", "main.py"),
      "import subprocess\nsubprocess.run(request.args.get('cmd'))\n",
    );
    const ctx = createMockToolContext({ cwd: root, target: root });
    const tool = createTaintIrisNextModule().tools.find(
      (candidate) => candidate.name === "taint-iris-next:hunt",
    );

    const result = await tool?.execute({ target: root, mode: "plan", maxCatalogEntries: 3 }, ctx);
    expect(result?.ok).toBe(true);
    expect(result?.output).toContain("threat model: warning");
    expect(result?.output).toContain("threat-model-empty");
  }, 20_000);

  it("accepts persisted app-model context even when flat repo context is sparse", () => {
    const root = tempRepo();
    mkdirSync(path.join(root, ".kuzushi"), { recursive: true });
    writeFileSync(
      path.join(root, ".kuzushi", "context-snapshot.json"),
      `${JSON.stringify(
        {
          target: root,
          timestamp: Date.now(),
          discovery: "flat",
          options: { enrichment: true, threatModel: true },
          repoContext: repoContext({ authPatterns: ["middleware-guards"] }),
          fileIndex: { tree: [], totalFiles: 12 },
          appModel: {
            routes: [],
            outboundClients: [
              {
                id: "requests|client.py|12",
                kind: "requests",
                filePath: "client.py",
                startLine: 12,
                symbol: "requests.get",
              },
            ],
          },
        },
        null,
        2,
      )}\n`,
    );
    writePersistentThreatModel(root, threatModel(["CWE-918"]));

    const artifacts = resolveTaintIrisNextPersistentArtifacts(root);
    expect(artifacts.contextStatus.ok).toBe(true);
  });

  it("resolves parent .kuzushi context and threat model for subdirectory targets", async () => {
    const root = tempRepo();
    const lab = path.join(root, "lab");
    mkdirSync(lab, { recursive: true });
    writePersistentContext(
      root,
      repoContext({
        languages: ["Python"],
        frameworks: ["Django"],
        ormOrDb: ["PostgreSQL"],
        entryPoints: ["lab/app.py"],
      }),
    );
    writePersistentThreatModel(root, threatModel(["CWE-89"]));
    const artifacts = resolveTaintIrisNextPersistentArtifacts(lab);
    expect(artifacts.contextStatus.ok).toBe(true);
    expect(artifacts.threatModelStatus.ok).toBe(true);

    const ctx = createMockToolContext({ cwd: root, target: lab });
    const tool = createTaintIrisNextModule().tools.find(
      (candidate) => candidate.name === "taint-iris-next:hunt",
    );

    const result = await tool?.execute({ target: lab, mode: "plan", maxCatalogEntries: 1 }, ctx);
    expect(result?.ok).toBe(true);
    expect(result?.output).toContain(path.join(root, ".kuzushi", "context-snapshot.json"));
    expect(result?.output).toContain(path.join(root, ".kuzushi", "threat-model.json"));
  });

  it("maps CodeQL findings into catalog-scoped evidence rows", () => {
    const root = tempRepo();
    const context = repoContext({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      ormOrDb: ["PostgreSQL"],
      entryPoints: ["src/routes.ts"],
    });
    const ctx = seededContext(root, context, threatModel(["CWE-89"]));
    const plan = buildTaintIrisNextPlan(
      { target: root, maxCatalogEntries: 1, maxBudgetUsd: 0.05 },
      ctx,
    );
    const evidence = codeqlFindingsToEvidence(
      [
        {
          taskId: "codeql",
          fingerprint: "fp",
          ruleId: "js/sql-injection",
          filePath: "src/routes.ts",
          startLine: 2,
          severity: "ERROR",
          message: "Database query built from user-controlled data.",
          evidence: "req.query.id flows to db.query(sql)",
          scannerConfidence: "HIGH",
          subcategory: ["vuln"],
          likelihood: "HIGH",
          impact: "HIGH",
          cwe: ["CWE-89"],
          score: 90,
          taintPath: [
            {
              filePath: "src/routes.ts",
              line: 1,
              message: "source",
              snippet: "req.query.id",
            },
            {
              filePath: "src/routes.ts",
              line: 2,
              message: "sink",
              snippet: "db.query(sql)",
            },
          ],
        },
      ],
      plan,
    );

    expect(evidence).toEqual([
      expect.objectContaining({
        cwe: "CWE-89",
        role: "source",
        pattern: "js/sql-injection",
        catalogSignal: "codeql: js/sql-injection",
        confidence: "high",
      }),
      expect.objectContaining({
        cwe: "CWE-89",
        role: "sink",
        filePath: "src/routes.ts",
      }),
    ]);
  });

  it("generates a bounded JavaScript CodeQL candidate query from the catalog", () => {
    const root = tempRepo();
    const context = repoContext({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      ormOrDb: ["PostgreSQL"],
      entryPoints: ["src/routes.ts"],
    });
    const ctx = seededContext(root, context, threatModel(["CWE-89"]));
    const plan = buildTaintIrisNextPlan(
      { target: root, maxCatalogEntries: 1, maxBudgetUsd: 0.05 },
      ctx,
    );

    const query = buildCodeqlCatalogQuery(plan, "javascript");
    expect(query).toContain("Taint IRIS Next bounded catalog candidates");
    expect(query).toContain('cwe = "CWE-89"');
    expect(query).toContain("CallExpr call");
    expect(buildCodeqlCatalogQuery(plan, "ruby")).toBeNull();
  });

  it("generates a Python CodeQL path-problem query from the catalog", () => {
    const root = tempRepo();
    const context = repoContext({
      languages: ["Python"],
      frameworks: ["FastAPI"],
      ormOrDb: ["SQLAlchemy"],
      entryPoints: ["lab/app.py"],
    });
    const ctx = seededContext(root, context, threatModel(["CWE-89"]));
    const basePlan = buildTaintIrisNextPlan({ target: root, maxCatalogEntries: 10 }, ctx);
    const sqlCatalogEntry = TAINT_IRIS_NEXT_CWE_CATALOG.find((entry) => entry.cwe === "CWE-89");
    expect(sqlCatalogEntry).toBeDefined();
    const plan = {
      ...basePlan,
      catalog: [sqlCatalogEntry!],
      structuralQueries: buildStructuralQueriesFromCatalog([sqlCatalogEntry!]),
    };

    const query = buildCodeqlCatalogQuery(plan, "python");
    expect(query).toContain("@kind path-problem");
    expect(query).toContain("import python");
    expect(query).toContain("TaintTracking::Global");
    expect(query).toContain("PathGraph");
    expect(query).toContain("RemoteFlowSources");
    expect(query).toContain('cwe = "CWE-89"');
  });

  it("generates per-CWE Python CodeQL path queries for taint classes", () => {
    const root = tempRepo();
    const wanted = new Set([
      "CWE-22",
      "CWE-78",
      "CWE-79",
      "CWE-89",
      "CWE-94",
      "CWE-502",
      "CWE-611",
      "CWE-918",
    ]);
    const entries = TAINT_IRIS_NEXT_CWE_CATALOG.filter((entry) => wanted.has(entry.cwe));
    const context = repoContext({
      languages: ["Python"],
      frameworks: ["FastAPI"],
      ormOrDb: ["SQLAlchemy"],
      entryPoints: ["lab/app.py"],
    });
    const ctx = seededContext(root, context, threatModel([...wanted]));
    const basePlan = buildTaintIrisNextPlan({ target: root, maxCatalogEntries: 20 }, ctx);
    const plan = {
      ...basePlan,
      catalog: entries,
      structuralQueries: buildStructuralQueriesFromCatalog(entries),
    };

    const queries = buildCodeqlCatalogQueries(plan, "python");
    expect(new Set(queries.map((query) => query.cwe))).toEqual(wanted);
    for (const query of queries) {
      expect(query.query).toContain("@kind path-problem");
      expect(query.query).toContain("TaintTracking::Global");
      expect(query.query).toContain(`cwe = "${query.cwe}"`);
    }
  });

  it("does not send authz/control CWEs through generic Python taint path generation", () => {
    const root = tempRepo();
    const entry = TAINT_IRIS_NEXT_CWE_CATALOG.find((candidate) => candidate.cwe === "CWE-862");
    expect(entry).toBeDefined();
    const context = repoContext({ languages: ["Python"], frameworks: ["FastAPI"] });
    const ctx = seededContext(root, context, threatModel(["CWE-862"]));
    const basePlan = buildTaintIrisNextPlan({ target: root, maxCatalogEntries: 1 }, ctx);
    const plan = {
      ...basePlan,
      catalog: [entry!],
      structuralQueries: buildStructuralQueriesFromCatalog([entry!]),
    };

    expect(buildCodeqlCatalogQueries(plan, "python")).toEqual([]);
    expect(buildCodeqlCatalogQuery(plan, "python")).toBeNull();
  });

  it("splits large generated Python CodeQL predicates into chunks", () => {
    const root = tempRepo();
    const sql = TAINT_IRIS_NEXT_CWE_CATALOG.find((entry) => entry.cwe === "CWE-89");
    expect(sql).toBeDefined();
    const expanded = {
      ...sql!,
      sinkSignals: Array.from({ length: 18 }, (_, index) => `sinkMethod${index}`),
    };
    const context = repoContext({
      languages: ["Python"],
      frameworks: ["FastAPI"],
      ormOrDb: ["SQLAlchemy"],
    });
    const ctx = seededContext(root, context, threatModel(["CWE-89"]));
    const basePlan = buildTaintIrisNextPlan(
      { target: root, maxCatalogEntries: 1, maxSpecsPerCwe: 18 },
      ctx,
    );
    const plan = {
      ...basePlan,
      catalog: [expanded],
      structuralQueries: buildStructuralQueriesFromCatalog([expanded]),
    };

    const query = buildCodeqlCatalogQuery(plan, "python");
    expect(query).toContain("irisSinkSpecChunk0");
    expect(query).toContain("irisSinkSpecChunk1");
    expect(query).toContain("irisSinkSpecChunk2");
  });

  it("converts Python CodeQL path findings into scoped source/step/sink evidence", () => {
    const root = tempRepo();
    const context = repoContext({
      languages: ["Python"],
      frameworks: ["FastAPI"],
      ormOrDb: ["SQLAlchemy"],
      entryPoints: ["lab/app.py"],
    });
    const ctx = seededContext(root, context, threatModel(["CWE-89"]));
    const plan = buildTaintIrisNextPlan(
      { target: path.join(root, "lab"), maxCatalogEntries: 1, maxEvidencePerCwe: 10 },
      ctx,
    );
    const findings: Finding[] = [
      {
        taskId: "codeql",
        fingerprint: "f1",
        ruleId: "py/taint-iris-next/catalog-taint-path",
        filePath: "lab/app.py",
        startLine: 20,
        severity: "WARNING",
        message: "Taint IRIS Next CWE-89 path from user input to sink catalog signal execute.",
        evidence: null,
        scannerConfidence: "MEDIUM",
        subcategory: ["vuln"],
        likelihood: "MEDIUM",
        impact: "MEDIUM",
        cwe: [],
        score: 1,
        proofState: "symbolic_only",
        engineProvenance: [{ kind: "codeql", detail: "test" }],
        taintPath: [
          {
            filePath: "lab/app.py",
            line: 10,
            message: "source",
            snippet: "q = request.query_params",
          },
          { filePath: "lab/service.py", line: 15, message: "step", snippet: "sql = q" },
          { filePath: "lab/app.py", line: 20, message: "sink", snippet: "session.execute(sql)" },
        ],
      },
      {
        taskId: "codeql",
        fingerprint: "f2",
        ruleId: "py/taint-iris-next/catalog-taint-path",
        filePath: "other/app.py",
        startLine: 1,
        severity: "WARNING",
        message: "Taint IRIS Next CWE-89 path from user input to sink catalog signal execute.",
        evidence: null,
        scannerConfidence: "MEDIUM",
        subcategory: ["vuln"],
        likelihood: "MEDIUM",
        impact: "MEDIUM",
        cwe: [],
        score: 1,
        proofState: "symbolic_only",
        engineProvenance: [{ kind: "codeql", detail: "test" }],
        taintPath: [
          { filePath: "other/app.py", line: 1, message: "sink", snippet: "execute(sql)" },
        ],
      },
    ];

    const evidence = codeqlFindingsToEvidence(findings, plan);
    expect(evidence.map((item) => item.role)).toEqual(["source", "structural", "sink"]);
    expect(evidence.every((item) => item.filePath.startsWith("lab/"))).toBe(true);
    expect(evidence[0]?.catalogSignal).toContain("CWE-89");
    expect(evidence[2]?.language).toBe("python");
  });

  it("extracts capped structural evidence with snippets and ignored directories", async () => {
    const root = tempRepo();
    mkdirSync(path.join(root, "src"), { recursive: true });
    mkdirSync(path.join(root, "node_modules", "pkg"), { recursive: true });
    writeFileSync(
      path.join(root, "src", "routes.ts"),
      [
        "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;",
        "db.query(sql);",
        "db.execute(sql);",
      ].join("\n"),
    );
    writeFileSync(path.join(root, "node_modules", "pkg", "bad.ts"), "db.query(req.query.id);\n");

    const context = repoContext({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      ormOrDb: ["PostgreSQL"],
      entryPoints: ["src/routes.ts"],
    });
    const model = threatModel(["CWE-89"]);
    const ctx = seededContext(root, context, model);
    const plan = buildTaintIrisNextPlan(
      { target: root, maxCatalogEntries: 1, maxEvidencePerCwe: 2, maxFilesPerQuery: 1 },
      ctx,
    );

    const result = await runStructuralExtractor(plan, ctx);
    expect(result.evidence.length).toBeGreaterThanOrEqual(2);
    expect(result.evidence.every((item) => item.cwe === "CWE-89")).toBe(true);
    expect(result.evidence.every((item) => item.filePath.startsWith("src/"))).toBe(true);
    expect(result.evidence.some((item) => item.role === "sink")).toBe(true);
    expect(result.evidence[0]).toEqual(
      expect.objectContaining({
        language: "typescript",
        catalogSignal: expect.any(String),
        snippet: expect.any(String),
      }),
    );
  });

  it("renders the bounded agent prompt with attribution, backend, catalog, and evidence", async () => {
    const root = tempRepo();
    mkdirSync(path.join(root, "src"), { recursive: true });
    writeFileSync(path.join(root, "src", "routes.ts"), "db.query(req.query.id);\n");
    const context = repoContext({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      ormOrDb: ["PostgreSQL"],
      entryPoints: ["src/routes.ts"],
    });
    const model = threatModel(["CWE-89"]);
    const ctx = seededContext(root, context, model);
    const plan = buildTaintIrisNextPlan({ target: root, maxCatalogEntries: 3 }, ctx);
    const evidence = await runStructuralExtractor(plan, ctx);

    const prompt = buildTaintIrisNextAgentPrompt(plan, evidence);
    expect(prompt).toContain("IRIS: LLM-Assisted Static Analysis");
    expect(prompt).toContain("## CWE Candidate Catalog");
    expect(prompt).toContain("## Evidence Bundles");
    expect(prompt).toContain("selected: structural");
    expect(prompt).toContain("Return strict JSON");
  });

  it("keeps plan mode deterministic and does not call the runtime agent", async () => {
    const root = tempRepo();
    mkdirSync(path.join(root, "src"), { recursive: true });
    writeFileSync(path.join(root, "src", "routes.ts"), "db.query(req.query.id);\n");
    const runtime = createFakeRuntime([{ match: /Taint IRIS Next/u, output: "{}" }]);
    const context = repoContext({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      ormOrDb: ["PostgreSQL"],
      entryPoints: ["src/routes.ts"],
    });
    const ctx = createMockToolContext({
      cwd: root,
      target: root,
      runtime,
      seedTaskOutputs: new Map<string, unknown>([
        ["context-gatherer", { repoContext: context }],
        ["threat-model-randori", { document: threatModel(["CWE-89"]), findings: [] }],
      ]),
    });
    const tool = createTaintIrisNextModule().tools.find(
      (candidate) => candidate.name === "taint-iris-next:hunt",
    );

    const result = await tool?.execute({ target: root, mode: "plan", maxCatalogEntries: 1 }, ctx);
    expect(result?.ok).toBe(true);
    expect(runtime.calls).toHaveLength(0);
    expect(result?.data).toEqual(
      expect.objectContaining({
        status: "planned",
        agentPrompt: expect.stringContaining("CWE Candidate Catalog"),
      }),
    );
    expect(getRecordedActivity(ctx).map((call) => call.meta?.phase)).toContain("backend-evidence");
  });

  it("runs hunt mode with a mocked agent and normalizes findings with provenance", async () => {
    const root = tempRepo();
    mkdirSync(path.join(root, "src"), { recursive: true });
    writeFileSync(path.join(root, "src", "routes.ts"), "db.query(req.query.id);\n");
    const runtime = createFakeRuntime([
      {
        match: /Taint IRIS Next agent/u,
        output: "{}",
        structuredOutput: {
          selectedCwes: [
            {
              cwe: "CWE-89",
              reason: "raw query receives request data",
              catalogSignals: ["sink: query"],
              sourceSpec: "request query parameters",
              sinkSpec: "database query calls",
              sanitizerSpec: "parameterized query APIs",
              customCweRationale: "",
            },
          ],
          findings: [
            {
              title: "Request parameter reaches raw SQL query",
              cwe: "CWE-89",
              severity: "high",
              confidence: "medium",
              evidenceLevel: "linked",
              filePath: "src/routes.ts",
              startLine: 1,
              message: "The query uses request-controlled data in SQL construction.",
              sourceSinkTrace: "req.query.id -> db.query(sql)",
              catalogSignals: ["source: query parameter", "sink: query"],
              customCweRationale: "",
              taintPath: [
                {
                  filePath: "src/routes.ts",
                  line: 1,
                  message: "source and SQL construction",
                  snippet: "db.query(req.query.id)",
                },
              ],
            },
          ],
          triage: [
            {
              status: "finding",
              cwe: "CWE-89",
              evidenceLevel: "linked",
              rationale: "request data reaches raw SQL query",
              filePath: "src/routes.ts",
              line: 1,
              catalogSignals: ["sink: query"],
            },
          ],
          notes: [],
        },
      },
    ]);
    const context = repoContext({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      ormOrDb: ["PostgreSQL"],
      entryPoints: ["src/routes.ts"],
    });
    const ctx = createMockToolContext({
      cwd: root,
      target: root,
      runtime,
      seedTaskOutputs: new Map<string, unknown>([
        ["context-gatherer", { repoContext: context }],
        ["threat-model-randori", { document: threatModel(["CWE-89"]), findings: [] }],
      ]),
    });
    const tool = createTaintIrisNextModule().tools.find(
      (candidate) => candidate.name === "taint-iris-next:hunt",
    );

    const result = await tool?.execute(
      { target: root, mode: "hunt", maxCatalogEntries: 1, minEvidenceLevel: "candidate" },
      ctx,
    );
    expect(result?.ok).toBe(true);
    expect(runtime.calls).toHaveLength(1);

    const data = result?.data as {
      findings: Array<{ cwe: string[]; engineProvenance: unknown[] }>;
    };
    expect(data.findings).toHaveLength(1);
    expect(data.findings[0]?.cwe).toEqual(["CWE-89"]);
    expect(data.findings[0]?.engineProvenance).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ detail: expect.stringContaining("taint-iris-next") }),
      ]),
    );
  });

  it.each([
    [
      "claude",
      () =>
        backendRuntime("claude", [
          {
            match: /Taint IRIS Next agent/u,
            output: "{}",
            structuredOutput: {
              selectedCwes: [
                {
                  cwe: "CWE-89",
                  reason: "catalog and threat model selected SQL injection",
                  catalogSignals: ["sink: query"],
                  sourceSpec: "request query parameter",
                  sinkSpec: "database query",
                  sanitizerSpec: "",
                  customCweRationale: "",
                },
              ],
              findings: [],
              triage: [],
              notes: [],
            },
          },
        ]),
    ],
    [
      "codex",
      () =>
        streamedRuntime("codex", [
          {
            type: "text-delta",
            delta:
              '```json\n{"selectedCwes":[{"cwe":"CWE-89","reason":"catalog and threat model selected SQL injection","catalogSignals":["sink: query"],"sourceSpec":"request query parameter","sinkSpec":"database query","sanitizerSpec":"","customCweRationale":""}],"findings":[],"triage":[],"notes":[]}\n```',
          },
          {
            type: "result",
            subtype: "success",
            result: "",
            totalCostUsd: 0.03,
          },
        ]),
    ],
  ] as const)("normalizes %s agent output through the backend-neutral adapter", async (_, makeRuntime) => {
    const root = tempRepo();
    const context = repoContext({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      ormOrDb: ["PostgreSQL"],
    });
    const ctx = seededContext(root, context, threatModel(["CWE-89"]));
    const plan = buildTaintIrisNextPlan(
      { target: root, maxCatalogEntries: 1, maxBudgetUsd: 0.05 },
      ctx,
    );
    const runtime = makeRuntime();
    const agentCtx = createMockToolContext({
      cwd: root,
      target: root,
      runtime,
      ...(runtime.id === "codex" ? { config: { model: "codex:gpt-5.5" } } : {}),
      seedTaskOutputs: ctx.seedTaskOutputs,
    });

    const result = await runTaintIrisNextAgent(plan, evidenceResult({}), agentCtx);

    expect(result.agentRuntimeBackend).toBe(runtime.id);
    expect(result.agentStatus).toBe("valid-json");
    expect(result.structuredOutputValid).toBe(true);
    expect(result.selectedCwes.map((item) => item.cwe)).toEqual(["CWE-89"]);
    expect(runtime.calls[0]?.options.maxBudgetUsd).toBe(0.05);
    expect(runtime.calls[0]?.options.abortController).toBeDefined();
    expect(runtime.calls[0]?.options.outputFormat).toEqual(
      expect.objectContaining({ strict: true }),
    );
    expect(runtime.calls[0]?.options.model).toBe(
      runtime.id === "codex" ? "codex:gpt-5.5" : "anthropic:claude-sonnet-4-6",
    );
  });

  it("rejects runtime/model mismatches instead of silently falling back", async () => {
    const root = tempRepo();
    const context = repoContext({ languages: ["TypeScript"], frameworks: ["Express"] });
    const ctx = seededContext(root, context, threatModel(["CWE-89"]));
    const plan = buildTaintIrisNextPlan({ target: root, maxCatalogEntries: 1 }, ctx);
    const runtime = backendRuntime("codex", [
      {
        match: /Taint IRIS Next agent/u,
        output: '{"selectedCwes":[],"findings":[],"triage":[],"notes":[]}',
      },
    ]);
    const agentCtx = createMockToolContext({
      cwd: root,
      target: root,
      runtime,
      seedTaskOutputs: ctx.seedTaskOutputs,
    });

    await expect(runTaintIrisNextAgent(plan, evidenceResult({}), agentCtx)).rejects.toThrow(
      /will not silently switch models/u,
    );
    expect(runtime.calls).toHaveLength(0);
  });

  it("does not treat unrelated runtime-error JSON as valid agent output", async () => {
    const root = tempRepo();
    const context = repoContext({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      ormOrDb: ["PostgreSQL"],
    });
    const ctx = seededContext(root, context, threatModel(["CWE-89"]));
    const plan = buildTaintIrisNextPlan({ target: root, maxCatalogEntries: 1 }, ctx);
    const runtime = streamedRuntime("codex", [
      {
        type: "result",
        subtype: "success",
        result: 'runtime failed with {"type":"error","message":"model unsupported"}',
        totalCostUsd: 0,
      },
    ]);
    const agentCtx = createMockToolContext({
      cwd: root,
      target: root,
      runtime,
      config: { model: "codex:gpt-5.5" },
      seedTaskOutputs: ctx.seedTaskOutputs,
    });

    const result = await runTaintIrisNextAgent(plan, evidenceResult({}), agentCtx);

    expect(result.agentRuntimeBackend).toBe("codex");
    expect(result.agentStatus).toBe("invalid-json");
    expect(result.structuredOutputValid).toBe(false);
    expect(result.parseError).toContain("did not match IRIS agent output schema");
  });

  it("skips JSON repair retry once the first agent call reaches the run budget", async () => {
    const root = tempRepo();
    const context = repoContext({ languages: ["TypeScript"], frameworks: ["Express"] });
    const ctx = seededContext(root, context, threatModel(["CWE-89"]));
    const plan = buildTaintIrisNextPlan(
      { target: root, maxCatalogEntries: 1, maxBudgetUsd: 0.05 },
      ctx,
    );
    const runtime = backendRuntime("claude", [
      {
        match: /Taint IRIS Next agent/u,
        output: "not json",
        costUsd: 0.08,
      },
      {
        match: /Return only strict JSON/u,
        output: '{"selectedCwes":[],"findings":[],"triage":[],"notes":[]}',
        costUsd: 0.01,
      },
    ]);
    const agentCtx = createMockToolContext({
      cwd: root,
      target: root,
      runtime,
      seedTaskOutputs: ctx.seedTaskOutputs,
    });

    const result = await runTaintIrisNextAgent(plan, evidenceResult({}), agentCtx);

    expect(runtime.calls).toHaveLength(1);
    expect(result.agentStatus).toBe("invalid-json");
    expect(result.warnings.join(" ")).toContain("repair retry skipped");
  });

  it("returns ranked structural review candidates when pi-ai returns invalid JSON", async () => {
    const root = tempRepo();
    const context = repoContext({ languages: ["Python"] });
    const ctx = seededContext(root, context, threatModel(["CWE-78", "CWE-117"]));
    const plan = buildTaintIrisNextPlan({ target: root, maxCatalogEntries: 2 }, ctx);
    const runtime = backendRuntime("pi-ai", [
      { match: /Taint IRIS Next agent/u, output: "I found command execution but no JSON." },
      { match: /Return only strict JSON/u, output: "still not json" },
    ]);
    const candidates = [
      taintCandidate({
        id: "cmd-source",
        cwe: "CWE-78",
        role: "source",
        filePath: "exec.py",
        line: 10,
        snippet: "def run(command):",
        pattern: "command",
      }),
      taintCandidate({
        id: "cmd-sink",
        cwe: "CWE-78",
        role: "sink",
        filePath: "exec.py",
        line: 12,
        snippet: "subprocess.Popen(command, shell=True)",
        pattern: "subprocess.Popen",
      }),
      taintCandidate({
        id: "log-source",
        cwe: "CWE-117",
        role: "source",
        filePath: "server.py",
        line: 20,
        snippet: "def start(name):",
        pattern: "name",
      }),
      taintCandidate({
        id: "log-sink",
        cwe: "CWE-117",
        role: "sink",
        filePath: "server.py",
        line: 30,
        snippet: "logger.info(\"Server '%s' connected\", name)",
        pattern: "logger.info",
      }),
    ];
    const agentCtx = createMockToolContext({
      cwd: root,
      target: root,
      runtime,
      seedTaskOutputs: ctx.seedTaskOutputs,
    });

    const result = await runTaintIrisNextAgent(
      plan,
      evidenceResult({
        candidates,
        linkedStories: [
          linkedStory({
            id: "log-1",
            cwe: "CWE-117",
            taintClass: "log-injection",
            sourceCandidateId: "log-source",
            sinkCandidateId: "log-sink",
            filePath: "server.py",
            sourceLine: 20,
            sinkLine: 30,
            sharedTokens: ["name"],
            enclosingSymbol: "start",
          }),
          linkedStory({
            id: "cmd-1",
            cwe: "CWE-78",
            taintClass: "os-command-injection",
            sourceCandidateId: "cmd-source",
            sinkCandidateId: "cmd-sink",
            filePath: "exec.py",
            sourceLine: 10,
            sinkLine: 12,
            sharedTokens: ["command"],
            enclosingSymbol: "run",
          }),
        ],
        linkedStoryCount: 2,
      }),
      agentCtx,
    );

    expect(runtime.calls).toHaveLength(2);
    expect(result.agentRuntimeBackend).toBe("pi-ai");
    expect(result.agentStatus).toBe("invalid-json");
    expect(result.structuredOutputValid).toBe(false);
    expect(result.reviewCandidates).toHaveLength(2);
    expect(result.findings[0]?.cwe).toEqual(["CWE-78"]);
    expect(result.warnings.join(" ")).toContain("agent output invalid");
  });

  it("rejects mocked agent output that selects an unknown CWE without rationale", async () => {
    const root = tempRepo();
    const context = repoContext({ languages: ["TypeScript"], frameworks: ["Express"] });
    const ctx = seededContext(root, context, threatModel(["CWE-89"]));
    const plan = buildTaintIrisNextPlan({ target: root, maxCatalogEntries: 3 }, ctx);
    const runtime = createFakeRuntime([
      {
        match: /Taint IRIS Next agent/u,
        output: "{}",
        structuredOutput: {
          selectedCwes: [
            {
              cwe: "CWE-9999",
              reason: "unknown",
              catalogSignals: [],
              sourceSpec: "",
              sinkSpec: "",
              sanitizerSpec: "",
              customCweRationale: "",
            },
          ],
          findings: [],
          triage: [],
          notes: [],
        },
      },
    ]);
    const agentCtx = createMockToolContext({
      cwd: root,
      target: root,
      runtime,
      seedTaskOutputs: ctx.seedTaskOutputs,
    });

    await expect(runTaintIrisNextAgent(plan, evidenceResult({}), agentCtx)).rejects.toThrow(
      /invalid CWEs/u,
    );
  });

  it("warns when evidence exists but the agent selects no CWEs", async () => {
    const root = tempRepo();
    const context = repoContext({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      ormOrDb: ["PostgreSQL"],
    });
    const ctx = seededContext(root, context, threatModel(["CWE-89"]));
    const plan = buildTaintIrisNextPlan({ target: root, maxCatalogEntries: 1 }, ctx);
    const runtime = createFakeRuntime([
      {
        match: /Taint IRIS Next agent/u,
        output: "{}",
        structuredOutput: {
          selectedCwes: [],
          findings: [],
          triage: [],
          notes: [],
        },
      },
    ]);
    const agentCtx = createMockToolContext({
      cwd: root,
      target: root,
      runtime,
      seedTaskOutputs: ctx.seedTaskOutputs,
    });

    const result = await runTaintIrisNextAgent(
      plan,
      evidenceResult({
        evidence: [
          {
            cwe: "CWE-89",
            taintClass: "sql-injection",
            role: "sink",
            pattern: "query",
            filePath: "src/routes.ts",
            line: 1,
            snippet: "db.query(req.query.id)",
            language: "typescript",
            confidence: "medium",
            catalogSignal: "sink: query",
          },
        ],
        queryCount: 1,
      }),
      agentCtx,
    );

    expect(result.warnings.join(" ")).toContain("agent selected no CWEs");
  });

  it("fails closed when the agent never returns valid strict JSON", async () => {
    const root = tempRepo();
    mkdirSync(path.join(root, "src"), { recursive: true });
    writeFileSync(path.join(root, "src", "routes.ts"), "db.query(req.query.id);\n");
    const runtime = createFakeRuntime([
      { match: /Taint IRIS Next agent/u, output: "I found some candidates but not JSON." },
      { match: /Return only strict JSON/u, output: "still not json" },
    ]);
    const ctx = createMockToolContext({
      cwd: root,
      target: root,
      runtime,
      seedTaskOutputs: new Map<string, unknown>([
        [
          "context-gatherer",
          {
            repoContext: repoContext({
              languages: ["TypeScript"],
              frameworks: ["Express"],
              ormOrDb: ["PostgreSQL"],
            }),
          },
        ],
        ["threat-model-randori", { document: threatModel(["CWE-89"]), findings: [] }],
      ]),
    });
    const tool = createTaintIrisNextModule().tools.find(
      (candidate) => candidate.name === "taint-iris-next:hunt",
    );

    const result = await tool?.execute(
      { target: root, mode: "hunt", maxCatalogEntries: 1, minEvidenceLevel: "path" },
      ctx,
    );
    expect(result?.ok).toBe(false);
    expect(runtime.calls).toHaveLength(2);
    expect(result?.output).toContain("agent-output-invalid");
    expect(result?.output).toContain("agent output: invalid strict JSON");
    expect(result?.data).toEqual(
      expect.objectContaining({
        status: "agent-output-invalid",
        structuredOutputValid: false,
        structuredOutputRetryCount: 1,
      }),
    );
  });

  it("threads the ranked catalog and structural query seeds through taint-iris-next output", async () => {
    const root = tempRepo();
    mkdirSync(path.join(root, "src"), { recursive: true });
    writeFileSync(path.join(root, "src", "routes.ts"), "fetch(req.query.url);\ndb.query(sql);\n");
    const context = repoContext({
      languages: ["TypeScript"],
      frameworks: ["Express"],
      ormOrDb: ["PostgreSQL"],
      entryPoints: ["src/routes.ts"],
    });
    const ctx = createMockToolContext({
      cwd: root,
      target: root,
      seedTaskOutputs: new Map<string, unknown>([
        ["context-gatherer", { repoContext: context }],
        ["threat-model-randori", { document: threatModel(["CWE-918"]), findings: [] }],
      ]),
    });
    const tool = createTaintIrisNextModule().tools.find(
      (candidate) => candidate.name === "taint-iris-next:hunt",
    );

    const result = await tool?.execute({ target: root, maxCatalogEntries: 1 }, ctx);
    expect(result?.ok).toBe(true);
    expect(result?.output).toContain("CWE Candidate Catalog");
    expect(result?.output).toContain("CWE-918");

    const data = result?.data as {
      cweCatalog: Array<{ cwe: string }>;
      structuralQueries: Array<{ cwe: string; pattern: string }>;
      promptCatalog: string;
    };
    expect(data.cweCatalog).toHaveLength(1);
    expect(data.cweCatalog[0]?.cwe).toBe("CWE-918");
    expect(data.structuralQueries.some((query) => query.cwe === "CWE-918")).toBe(true);
    expect(data.promptCatalog).toContain("The agent must choose CWE themes from this catalog");
  });
});

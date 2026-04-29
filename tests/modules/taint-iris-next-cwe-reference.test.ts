import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
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
  buildCodeqlCatalogQuery,
  codeqlFindingsToEvidence,
  runStructuralExtractor,
} from "../../src/modules/taint-iris-next/extractors.js";
import {
  buildTaintIrisNextPlan,
  chooseBackend,
} from "../../src/modules/taint-iris-next/planner.js";
import { createTaintIrisNextModule } from "../../src/modules/taint-iris-next/taint-iris-next.js";
import type { Finding } from "../../src/scanners/types.js";
import {
  createFakeRuntime,
  createMockToolContext,
  getRecordedActivity,
} from "../../src/testing/index.js";
import type { RepoContext } from "../../src/types.js";

const SLOW_TAINT_IRIS_TIMEOUT_MS = 60_000;

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
    expect(auto.selected).toBe("codeql");
    expect(auto.codeqlDbPath).toBe(path.join(root, ".kuzushi", "codeql-db"));

    const explicit = chooseBackend("codeql", root);
    expect(explicit.selected).toBe("codeql");
    expect(explicit.codeqlDbPath).toBe(path.join(root, ".kuzushi", "codeql-db"));

    const missing = chooseBackend("codeql", path.join(root, "missing"));
    expect(missing.selected).toBe("structural");
    expect(missing.warnings.join(" ")).toContain("no existing CodeQL DB");
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
    const plan = buildTaintIrisNextPlan({ target: root, maxCatalogEntries: 1 }, ctx);
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
    const plan = buildTaintIrisNextPlan({ target: root, maxCatalogEntries: 1 }, ctx);

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
    expect(result.evidence).toHaveLength(2);
    expect(result.evidence.every((item) => item.cwe === "CWE-89")).toBe(true);
    expect(result.evidence.every((item) => item.filePath.startsWith("src/"))).toBe(true);
    expect(result.evidence[0]).toEqual(
      expect.objectContaining({
        language: "typescript",
        catalogSignal: expect.any(String),
        snippet: expect.any(String),
      }),
    );
  });

  it(
    "renders the bounded agent prompt with attribution, backend, catalog, and evidence",
    async () => {
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
    },
    SLOW_TAINT_IRIS_TIMEOUT_MS,
  );

  it(
    "keeps plan mode deterministic and does not call the runtime agent",
    async () => {
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
      expect(getRecordedActivity(ctx).map((call) => call.meta?.phase)).toContain(
        "backend-evidence",
      );
    },
    SLOW_TAINT_IRIS_TIMEOUT_MS,
  );

  it(
    "runs hunt mode with a mocked agent and normalizes findings with provenance",
    async () => {
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

      const result = await tool?.execute({ target: root, mode: "hunt", maxCatalogEntries: 1 }, ctx);
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
    },
    SLOW_TAINT_IRIS_TIMEOUT_MS,
  );

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

    await expect(
      runTaintIrisNextAgent(
        plan,
        { backend: "structural", tool: "rg", evidence: [], queryCount: 0, warnings: [] },
        agentCtx,
      ),
    ).rejects.toThrow(/invalid CWEs/u);
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
      {
        backend: "structural",
        tool: "rg",
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
        warnings: [],
      },
      agentCtx,
    );

    expect(result.warnings.join(" ")).toContain("agent selected no CWEs");
  });

  it(
    "threads the ranked catalog and structural query seeds through taint-iris-next output",
    async () => {
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
    },
    SLOW_TAINT_IRIS_TIMEOUT_MS,
  );
});

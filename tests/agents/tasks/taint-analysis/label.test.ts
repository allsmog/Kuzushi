import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { __taintAnalysisLabelInternals } from "../../../../src/agents/tasks/taint-analysis/label.js";
import type { TiPriorDocument } from "../../../../src/agents/tasks/taint-analysis/ti-prior.js";
import type {
  TaintAnalysisCandidate,
  TaintAnalysisLabelsDocument,
  TaintAnalysisPassEntry,
} from "../../../../src/agents/tasks/taint-analysis/types.js";
import { TAINT_ANALYSIS_PASSES } from "../../../../src/agents/tasks/taint-analysis/types.js";

const TMP_DIR = path.join(import.meta.dirname, "..", "..", "..", ".tmp-taint-analysis-label");

beforeEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
  mkdirSync(TMP_DIR, { recursive: true });
});

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

function makePassEntry(
  overrides: Partial<TaintAnalysisPassEntry> & {
    id: string;
    role: TaintAnalysisPassEntry["role"];
    callable: string;
    classification?: TaintAnalysisPassEntry["classification"];
    rationale?: string;
  },
): TaintAnalysisPassEntry {
  return {
    id: overrides.id,
    role: overrides.role,
    classification: overrides.classification ?? "candidate",
    confidence: overrides.confidence ?? 0.8,
    signature: {
      package: null,
      module: "pkg/mod",
      type: null,
      callable: overrides.callable,
      arg_index: 0,
      flow_kind: "argument",
      ...overrides.signature,
    },
    location: {
      file: "file.ext",
      line: 42,
      ...overrides.location,
    },
    rationale: overrides.rationale ?? "Original rationale.",
    evidence: overrides.evidence,
  };
}

function makeCandidate(
  overrides: Partial<TaintAnalysisCandidate> & {
    id: string;
    candidateKind: TaintAnalysisCandidate["candidateKind"];
    callable: string;
  },
): TaintAnalysisCandidate {
  return {
    id: overrides.id,
    candidateKind: overrides.candidateKind,
    callable: overrides.callable,
    flowKind: overrides.flowKind ?? "argument",
    receiverHint: overrides.receiverHint ?? "receiver",
    moduleHint: overrides.moduleHint ?? "module/path",
    argIndex: overrides.argIndex ?? 0,
    locationFile: overrides.locationFile ?? "file.ext",
    locationLine: overrides.locationLine ?? 20,
    snippet: overrides.snippet ?? "",
  };
}

function makeEntryFromCandidate(
  candidate: TaintAnalysisCandidate,
  overrides?: Partial<TaintAnalysisPassEntry>,
): TaintAnalysisPassEntry {
  return {
    id: candidate.id,
    role: candidate.candidateKind === "sink_candidate" ? "sink" : "source",
    classification: "candidate",
    confidence: 0.8,
    signature: {
      package: null,
      module: candidate.moduleHint ?? null,
      type: candidate.receiverHint ?? null,
      callable: candidate.callable,
      arg_index: candidate.argIndex,
      flow_kind: candidate.flowKind,
    },
    location: {
      file: candidate.locationFile,
      line: candidate.locationLine,
    },
    rationale: "From candidate.",
    ...overrides,
  };
}

describe("taint-analysis-label internals", () => {
  it("flags no-sources when preflight reports zero source rows", () => {
    const status = __taintAnalysisLabelInternals.resolveSourceAvailability(
      {
        extraction: { sourcesRowCount: 0 },
      } as unknown as Parameters<typeof __taintAnalysisLabelInternals.resolveSourceAvailability>[0],
      [
        {
          id: "sink-1",
          candidateKind: "sink_candidate",
          callable: "open",
          flowKind: "argument",
          receiverHint: null,
          moduleHint: "app.py",
          argIndex: 0,
          locationFile: "app.py",
          locationLine: 12,
        },
      ],
    );

    expect(status.noSourcesExtracted).toBe(true);
    expect(status.parsedSourceCount).toBe(0);
  });

  it("flags no-sources when parsed candidates contain no source markers", () => {
    const status = __taintAnalysisLabelInternals.resolveSourceAvailability(
      {
        extraction: { sourcesRowCount: 5 },
      } as unknown as Parameters<typeof __taintAnalysisLabelInternals.resolveSourceAvailability>[0],
      [
        {
          id: "sink-1",
          candidateKind: "sink_candidate",
          callable: "open",
          flowKind: "argument",
          receiverHint: null,
          moduleHint: "app.py",
          argIndex: 0,
          locationFile: "app.py",
          locationLine: 12,
        },
      ],
    );

    expect(status.noSourcesExtracted).toBe(true);
    expect(status.parsedSourceCount).toBe(0);
  });

  it("parses extraction CSV candidate rows", async () => {
    const csvPath = path.join(TMP_DIR, "sources.csv");
    writeFileSync(
      csvPath,
      [
        "col0,col1,col2,col3,col4,col5,col6,col7",
        "x,source_candidate,Query,flow_kind=return,receiver=req,module=backend/api.py,arg_index=-1,41",
        "x,source_candidate,Body,flow_kind=param,receiver=handler,module=backend/admin.py,arg_index=0,54",
      ].join("\n"),
      "utf-8",
    );

    const candidates = await __taintAnalysisLabelInternals.parseCsvCandidates(
      csvPath,
      "source_candidate",
    );
    expect(candidates).toHaveLength(2);
    expect(candidates[0].candidateKind).toBe("source_candidate");
    expect(candidates[0].callable).toBe("Query");
    expect(candidates[0].flowKind).toBe("return");
    expect(candidates[0].argIndex).toBeNull();
    expect(candidates[0].locationLine).toBe(41);
    expect(candidates[0].snippet).toBe("x");
    expect(candidates[1].argIndex).toBe(0);
    expect(candidates[1].flowKind).toBe("param");
    expect(candidates[1].snippet).toBe("x");
  });

  it("normalizes flow/line aliases and preserves CSV snippet", async () => {
    const csvPath = path.join(TMP_DIR, "sources-aliases.csv");
    writeFileSync(
      csvPath,
      [
        "col0,col1,col2,col3,col4,col5,col6,col7",
        '"request.body",source_candidate,Query,flow_kind=arg,receiver=req,module=backend/api.py,arg_index=0,line=123',
        '"request.params",source_candidate,Read,flow_kind=result,receiver=req,module=backend/api.py,arg_index=-1,line=77',
      ].join("\n"),
      "utf-8",
    );

    const candidates = await __taintAnalysisLabelInternals.parseCsvCandidates(
      csvPath,
      "source_candidate",
    );
    expect(candidates).toHaveLength(2);
    expect(candidates[0]).toMatchObject({
      callable: "Query",
      flowKind: "argument",
      argIndex: 0,
      locationLine: 123,
      snippet: "request.body",
    });
    expect(candidates[1]).toMatchObject({
      callable: "Read",
      flowKind: "return",
      argIndex: null,
      locationLine: 77,
      snippet: "request.params",
    });
  });

  it("parses quoted multiline CSV cells and preserves snippet payload", async () => {
    const csvPath = path.join(TMP_DIR, "sources-multiline.csv");
    writeFileSync(
      csvPath,
      [
        "col0,col1,col2,col3,col4,col5,col6,col7",
        '"first line',
        'second line, with ""quotes""",source_candidate,Raw,flow_kind=arg,receiver=queries,module=service/db.go,arg_index=0,line=321',
        '"single line",sink_candidate,From,flow_kind=argument,receiver=qm,module=service/db.go,arg_index=0,line=55',
      ].join("\n"),
      "utf-8",
    );

    const candidates = await __taintAnalysisLabelInternals.parseCsvCandidates(
      csvPath,
      "source_candidate",
    );
    expect(candidates).toHaveLength(2);
    expect(candidates[0]?.snippet).toBe('first line\nsecond line, with "quotes"');
    expect(candidates[0]?.flowKind).toBe("argument");
    expect(candidates[0]?.locationLine).toBe(321);
    expect(candidates[1]?.candidateKind).toBe("sink_candidate");
    expect(candidates[1]?.callable).toBe("From");
  });

  it("uses the same parser semantics for row counting and candidate parsing", async () => {
    const csvPath = path.join(TMP_DIR, "sources-row-parity.csv");
    writeFileSync(
      csvPath,
      [
        "col0,col1,col2,col3,col4,col5,col6,col7",
        '"alpha",source_candidate,Raw,flow_kind=argument,receiver=queries,module=a.go,arg_index=0,line=10',
        '"beta",source_candidate,From,flow_kind=arg,receiver=qm,module=b.go,arg_index=0,line=11',
        '"gamma",sink_candidate,ExecContext,flow_kind=argument,receiver=sql.DB,module=c.go,arg_index=1,line=22',
      ].join("\n"),
      "utf-8",
    );

    const candidates = await __taintAnalysisLabelInternals.parseCsvCandidates(
      csvPath,
      "source_candidate",
    );
    const content = readFileSync(csvPath, "utf-8");
    const sourceRows = __taintAnalysisLabelInternals.countCandidateCsvRecords(
      content,
      "source_candidate",
    );
    const sinkRows = __taintAnalysisLabelInternals.countCandidateCsvRecords(
      content,
      "sink_candidate",
    );
    const parsedSourceRows = candidates.filter(
      (candidate) => candidate.candidateKind === "source_candidate",
    ).length;
    const parsedSinkRows = candidates.filter(
      (candidate) => candidate.candidateKind === "sink_candidate",
    ).length;

    expect(sourceRows).toBe(parsedSourceRows);
    expect(sinkRows).toBe(parsedSinkRows);
  });

  it("builds label summary counts and top sinks/sources", () => {
    const labels: TaintAnalysisLabelsDocument = {
      version: "1.0.0",
      metadata: {
        run_id: "run-1",
        generated_at: new Date().toISOString(),
        language: "python",
        framework: "fastapi",
        model: "anthropic:claude-sonnet-4-6",
        project: "repo",
      },
      passes: [
        {
          pass_id: 1,
          focus: "Path Traversal",
          cwes: ["022"],
          entries: [
            {
              id: "e1",
              role: "source",
              classification: "candidate",
              confidence: 0.9,
              signature: {
                package: null,
                module: "fastapi",
                type: null,
                callable: "Query",
                arg_index: null,
                flow_kind: "return",
              },
              location: { file: "a.py", line: 1 },
              rationale: "r",
            },
            {
              id: "e2",
              role: "sink",
              classification: "candidate",
              confidence: 0.4,
              signature: {
                package: null,
                module: "builtins",
                type: null,
                callable: "open",
                arg_index: 0,
                flow_kind: "argument",
              },
              location: { file: "b.py", line: 2 },
              rationale: "r",
            },
          ],
        },
      ],
    };

    const summary = __taintAnalysisLabelInternals.summarizeLabels(labels, 0.55);
    expect(summary.labelCounts["pass1.source"]).toBe(1);
    expect(summary.labelCounts["pass1.sink"]).toBe(1);
    expect(summary.reviewSummary).toContain("low-confidence entries");
    expect(summary.reviewSummary).toContain("open(1)");
    expect(summary.reviewSummary).toContain("Query(1)");
  });

  it("validates minimal labels document contract", () => {
    const invalid: TaintAnalysisLabelsDocument = {
      version: "bad",
      metadata: {
        run_id: "",
        generated_at: new Date().toISOString(),
        language: "python",
        framework: null,
        model: "",
        project: "",
      },
      passes: [],
    };

    const error = __taintAnalysisLabelInternals.validateLabelsDocument(invalid);
    expect(error).toContain("version");
  });

  it("builds TAINT_MODEL with TI basis and confidence weighting", () => {
    const labels: TaintAnalysisLabelsDocument = {
      version: "1.0.0",
      metadata: {
        run_id: "run-2",
        generated_at: new Date().toISOString(),
        language: "python",
        framework: "fastapi",
        model: "anthropic:claude-sonnet-4-6",
        project: "repo",
      },
      passes: [
        {
          pass_id: 1,
          focus: "Path Traversal",
          cwes: ["022"],
          entries: [
            {
              id: "src-1",
              role: "source",
              classification: "tp",
              confidence: 0.5,
              signature: {
                package: null,
                module: "fastapi",
                type: null,
                callable: "Query",
                arg_index: null,
                flow_kind: "return",
              },
              location: { file: "api.py", line: 12 },
              rationale: "user input boundary",
            },
            {
              id: "sink-1",
              role: "sink",
              classification: "tp",
              confidence: 0.6,
              signature: {
                package: null,
                module: "os",
                type: null,
                callable: "open",
                arg_index: 0,
                flow_kind: "argument",
              },
              location: { file: "fs.py", line: 23 },
              rationale: "filesystem access",
            },
          ],
        },
      ],
    };

    const tiPrior: TiPriorDocument = {
      version: "1.0.0",
      generatedAt: new Date().toISOString(),
      mode: "live-required",
      degraded: false,
      errors: [],
      cwes: [
        {
          cwe: "CWE-22",
          focus: "Path Traversal",
          exploitationStory: "story",
          sourceArchetypes: ["HTTP params"],
          sinkArchetypes: ["file open"],
          sanitizers: ["realpath"],
          references: [
            {
              source: "cisa-kev",
              id: "CVE-2024-12345",
              url: "https://example.invalid/CVE-2024-12345",
              title: "example",
            },
          ],
          tiWeight: "HIGH",
          highPriority: ["download handlers"],
          commonFalsePositives: ["fixed base dir"],
          oftenExploitable: ["unsanitized join"],
        },
      ],
    };

    const taintModel = __taintAnalysisLabelInternals.buildTaintModelDocument(labels, tiPrior);
    const cwe22 = taintModel.cwes.find((entry) => entry.cwe === "CWE-22");

    expect(cwe22).toBeDefined();
    expect(cwe22?.sources[0]?.ti_basis).toContain("weight=HIGH");
    expect(cwe22?.sources[0]?.confidence).toBeCloseTo(0.6, 5);
    expect(cwe22?.sinks[0]?.sink_focus).toBe("argument[0]");
  });

  it("loads v2 checkpoint when pass/language/fingerprint match", async () => {
    const candidates: TaintAnalysisCandidate[] = [
      makeCandidate({
        id: "sink-1",
        candidateKind: "sink_candidate",
        callable: "ExecContext",
        receiverHint: "sql.DB",
        moduleHint: "database/sql",
        locationFile: "db.go",
        locationLine: 20,
      }),
      makeCandidate({
        id: "src-2",
        candidateKind: "source_candidate",
        callable: "Query",
        receiverHint: "http.Request",
        moduleHint: "net/http",
        argIndex: null,
        flowKind: "return",
        locationFile: "handler.go",
        locationLine: 11,
      }),
    ];
    const entries = candidates.map((candidate) => makeEntryFromCandidate(candidate));
    const candidateFingerprint =
      __taintAnalysisLabelInternals.computeCandidatesFingerprint(candidates);
    const checkpointPath = path.join(TMP_DIR, "pass1.v2.json");

    await __taintAnalysisLabelInternals.writePassCheckpointV2(
      checkpointPath,
      1,
      "go",
      candidateFingerprint,
      entries,
    );

    const loaded = __taintAnalysisLabelInternals.loadPassCheckpoint({
      checkpointPath,
      passId: 1,
      language: "go",
      candidates,
      candidateFingerprint,
    });

    expect(loaded.hit).toBe(true);
    if (loaded.hit) {
      expect(loaded.format).toBe("v2");
      expect(loaded.entries).toHaveLength(2);
      expect(loaded.deniedCount).toBe(0);
      expect(loaded.needsRewrite).toBe(false);
    }
  });

  it("rejects v2 checkpoint on fingerprint mismatch", async () => {
    const candidates: TaintAnalysisCandidate[] = [
      makeCandidate({ id: "sink-1", candidateKind: "sink_candidate", callable: "ExecContext" }),
    ];
    const entries = candidates.map((candidate) => makeEntryFromCandidate(candidate));
    const candidateFingerprint =
      __taintAnalysisLabelInternals.computeCandidatesFingerprint(candidates);
    const checkpointPath = path.join(TMP_DIR, "fingerprint-mismatch.v2.json");

    await __taintAnalysisLabelInternals.writePassCheckpointV2(
      checkpointPath,
      1,
      "go",
      "not-the-real-fingerprint",
      entries,
    );

    const loaded = __taintAnalysisLabelInternals.loadPassCheckpoint({
      checkpointPath,
      passId: 1,
      language: "go",
      candidates,
      candidateFingerprint,
    });

    expect(loaded.hit).toBe(false);
    if (!loaded.hit) {
      expect(loaded.reason).toContain("fingerprint mismatch");
    }
  });

  it("rejects v2 checkpoint on pass/language mismatch", async () => {
    const candidates: TaintAnalysisCandidate[] = [
      makeCandidate({ id: "sink-1", candidateKind: "sink_candidate", callable: "ExecContext" }),
    ];
    const entries = candidates.map((candidate) => makeEntryFromCandidate(candidate));
    const candidateFingerprint =
      __taintAnalysisLabelInternals.computeCandidatesFingerprint(candidates);
    const passMismatchPath = path.join(TMP_DIR, "pass-mismatch.v2.json");
    const languageMismatchPath = path.join(TMP_DIR, "lang-mismatch.v2.json");

    await __taintAnalysisLabelInternals.writePassCheckpointV2(
      passMismatchPath,
      2,
      "go",
      candidateFingerprint,
      entries,
    );
    await __taintAnalysisLabelInternals.writePassCheckpointV2(
      languageMismatchPath,
      1,
      "python",
      candidateFingerprint,
      entries,
    );

    const passMismatch = __taintAnalysisLabelInternals.loadPassCheckpoint({
      checkpointPath: passMismatchPath,
      passId: 1,
      language: "go",
      candidates,
      candidateFingerprint,
    });
    const languageMismatch = __taintAnalysisLabelInternals.loadPassCheckpoint({
      checkpointPath: languageMismatchPath,
      passId: 1,
      language: "go",
      candidates,
      candidateFingerprint,
    });

    expect(passMismatch.hit).toBe(false);
    expect(languageMismatch.hit).toBe(false);
    if (!passMismatch.hit) {
      expect(passMismatch.reason).toContain("pass mismatch");
    }
    if (!languageMismatch.hit) {
      expect(languageMismatch.reason).toContain("language mismatch");
    }
  });

  it("rejects v2 checkpoint on parser-version mismatch", async () => {
    const candidates: TaintAnalysisCandidate[] = [
      makeCandidate({ id: "sink-1", candidateKind: "sink_candidate", callable: "ExecContext" }),
    ];
    const entries = candidates.map((candidate) => makeEntryFromCandidate(candidate));
    const candidateFingerprint =
      __taintAnalysisLabelInternals.computeCandidatesFingerprint(candidates);
    const checkpointPath = path.join(TMP_DIR, "parser-version-mismatch.v2.json");

    await __taintAnalysisLabelInternals.writePassCheckpointV2(
      checkpointPath,
      1,
      "go",
      candidateFingerprint,
      entries,
    );

    const raw = JSON.parse(readFileSync(checkpointPath, "utf-8"));
    raw.parserVersion = __taintAnalysisLabelInternals.LABEL_PARSER_VERSION - 1;
    writeFileSync(checkpointPath, JSON.stringify(raw, null, 2), "utf-8");

    const loaded = __taintAnalysisLabelInternals.loadPassCheckpoint({
      checkpointPath,
      passId: 1,
      language: "go",
      candidates,
      candidateFingerprint,
    });

    expect(loaded.hit).toBe(false);
    if (!loaded.hit) {
      expect(loaded.reason).toContain("parser version mismatch");
    }
  });

  it("loads matching legacy checkpoint, applies deny-list, and marks rewrite required", () => {
    const candidates: TaintAnalysisCandidate[] = [
      makeCandidate({
        id: "sink-1",
        candidateKind: "sink_candidate",
        callable: "fmt.Sprintf",
        receiverHint: "fmt",
        moduleHint: "fmt",
        locationFile: "main.go",
        locationLine: 50,
      }),
    ];
    const legacyEntries: TaintAnalysisPassEntry[] = [
      makeEntryFromCandidate(candidates[0], {
        role: "sink",
        classification: "tp",
        rationale: "Legacy sink label.",
      }),
    ];
    const candidateFingerprint =
      __taintAnalysisLabelInternals.computeCandidatesFingerprint(candidates);
    const checkpointPath = path.join(TMP_DIR, "legacy-match.json");
    writeFileSync(checkpointPath, JSON.stringify(legacyEntries, null, 2), "utf-8");

    const loaded = __taintAnalysisLabelInternals.loadPassCheckpoint({
      checkpointPath,
      passId: 1,
      language: "go",
      candidates,
      candidateFingerprint,
    });

    expect(loaded.hit).toBe(true);
    if (loaded.hit) {
      expect(loaded.format).toBe("legacy");
      expect(loaded.deniedCount).toBe(1);
      expect(loaded.needsRewrite).toBe(true);
      expect(loaded.entries[0]?.role).toBe("none");
      expect(loaded.entries[0]?.classification).toBe("fp");
    }
  });

  it("rejects legacy checkpoint on fingerprint mismatch even when entry count matches", () => {
    const candidates: TaintAnalysisCandidate[] = [
      makeCandidate({ id: "sink-1", candidateKind: "sink_candidate", callable: "QueryRow" }),
    ];
    const mismatchEntries: TaintAnalysisPassEntry[] = [
      makeEntryFromCandidate(
        makeCandidate({ id: "sink-1", candidateKind: "sink_candidate", callable: "ExecContext" }),
        { role: "sink", classification: "tp" },
      ),
    ];
    const checkpointPath = path.join(TMP_DIR, "legacy-fingerprint-mismatch.json");
    writeFileSync(checkpointPath, JSON.stringify(mismatchEntries, null, 2), "utf-8");

    const loaded = __taintAnalysisLabelInternals.loadPassCheckpoint({
      checkpointPath,
      passId: 1,
      language: "go",
      candidates,
      candidateFingerprint: __taintAnalysisLabelInternals.computeCandidatesFingerprint(candidates),
    });

    expect(loaded.hit).toBe(false);
    if (!loaded.hit) {
      expect(loaded.reason).toContain("legacy fingerprint mismatch");
    }
  });

  it("rejects checkpoint when a non-first entry has invalid shape", () => {
    const candidates: TaintAnalysisCandidate[] = [
      makeCandidate({ id: "sink-1", candidateKind: "sink_candidate", callable: "ExecContext" }),
      makeCandidate({ id: "sink-2", candidateKind: "sink_candidate", callable: "QueryRow" }),
    ];
    const malformedEntries: unknown[] = [
      makeEntryFromCandidate(candidates[0]),
      {
        id: "sink-2",
        role: "sink",
        classification: "tp",
        confidence: 0.9,
        rationale: "broken",
        signature: "not-an-object",
        location: { file: "db.go", line: 22 },
      },
    ];
    const checkpointPath = path.join(TMP_DIR, "legacy-malformed-middle.json");
    writeFileSync(checkpointPath, JSON.stringify(malformedEntries, null, 2), "utf-8");

    const loaded = __taintAnalysisLabelInternals.loadPassCheckpoint({
      checkpointPath,
      passId: 1,
      language: "go",
      candidates,
      candidateFingerprint: __taintAnalysisLabelInternals.computeCandidatesFingerprint(candidates),
    });

    expect(loaded.hit).toBe(false);
    if (!loaded.hit) {
      expect(loaded.reason).toContain("shape invalid");
    }
  });

  it("writes v2 checkpoint envelope and supports load round-trip", async () => {
    const candidates: TaintAnalysisCandidate[] = [
      makeCandidate({
        id: "src-1",
        candidateKind: "source_candidate",
        callable: "Query",
        flowKind: "return",
        argIndex: null,
      }),
    ];
    const entries: TaintAnalysisPassEntry[] = [makeEntryFromCandidate(candidates[0])];
    const candidateFingerprint =
      __taintAnalysisLabelInternals.computeCandidatesFingerprint(candidates);
    const checkpointPath = path.join(TMP_DIR, "roundtrip.v2.json");

    await __taintAnalysisLabelInternals.writePassCheckpointV2(
      checkpointPath,
      1,
      "go",
      candidateFingerprint,
      entries,
    );

    const raw = JSON.parse(readFileSync(checkpointPath, "utf-8"));
    expect(raw.version).toBe(__taintAnalysisLabelInternals.LABEL_CHECKPOINT_VERSION);
    expect(raw.parserVersion).toBe(__taintAnalysisLabelInternals.LABEL_PARSER_VERSION);
    expect(raw.passId).toBe(1);
    expect(raw.language).toBe("go");
    expect(raw.candidateFingerprint).toBe(candidateFingerprint);
    expect(Array.isArray(raw.entries)).toBe(true);

    const loaded = __taintAnalysisLabelInternals.loadPassCheckpoint({
      checkpointPath,
      passId: 1,
      language: "go",
      candidates,
      candidateFingerprint,
    });
    expect(loaded.hit).toBe(true);
    if (loaded.hit) {
      expect(loaded.format).toBe("v2");
      expect(loaded.entries).toHaveLength(1);
      expect(loaded.entries[0]?.id).toBe("src-1");
    }
  });

  it("reclassifies Go format/log sink callables via deny-list", () => {
    const entries: TaintAnalysisPassEntry[] = [
      makePassEntry({ id: "sink-1", role: "sink", callable: "fmt.Sprintf", classification: "tp" }),
      makePassEntry({
        id: "sink-2",
        role: "sink",
        callable: "Errorf",
        classification: "candidate",
      }),
    ];

    const updated = __taintAnalysisLabelInternals.applySinkDenyList(entries, "go");
    expect(updated).toHaveLength(2);
    expect(updated[0]?.role).toBe("none");
    expect(updated[0]?.classification).toBe("fp");
    expect(updated[1]?.role).toBe("none");
    expect(updated[1]?.classification).toBe("fp");
  });

  it("preserves legitimate Go sinks not present in deny-list", () => {
    const entries: TaintAnalysisPassEntry[] = [
      makePassEntry({ id: "sink-1", role: "sink", callable: "ExecContext", classification: "tp" }),
      makePassEntry({
        id: "sink-2",
        role: "sink",
        callable: "QueryRow",
        classification: "candidate",
      }),
    ];

    const updated = __taintAnalysisLabelInternals.applySinkDenyList(entries, "go");
    expect(updated[0]?.role).toBe("sink");
    expect(updated[0]?.classification).toBe("tp");
    expect(updated[1]?.role).toBe("sink");
    expect(updated[1]?.classification).toBe("candidate");
  });

  it("does not reclassify non-sink entries even when callable is deny-listed", () => {
    const entries: TaintAnalysisPassEntry[] = [
      makePassEntry({ id: "src-1", role: "source", callable: "Sprintf", classification: "tp" }),
    ];

    const updated = __taintAnalysisLabelInternals.applySinkDenyList(entries, "go");
    expect(updated[0]?.role).toBe("source");
    expect(updated[0]?.classification).toBe("tp");
  });

  it("preserves rationale and appends deny-list override note", () => {
    const entries: TaintAnalysisPassEntry[] = [
      makePassEntry({
        id: "sink-1",
        role: "sink",
        callable: "Sprintf",
        rationale: "Looks like formatter call.",
      }),
    ];

    const updated = __taintAnalysisLabelInternals.applySinkDenyList(entries, "go");
    expect(updated[0]?.rationale).toContain("Looks like formatter call.");
    expect(updated[0]?.rationale).toContain(
      "[Overridden: Sprintf is a formatting/logging function, not a security-sensitive sink.]",
    );
  });

  it("reclassifies Python formatting/logging callables via deny-list", () => {
    const entries: TaintAnalysisPassEntry[] = [
      makePassEntry({ id: "sink-1", role: "sink", callable: "format" }),
      makePassEntry({ id: "sink-2", role: "sink", callable: "print" }),
    ];

    const updated = __taintAnalysisLabelInternals.applySinkDenyList(entries, "python");
    expect(updated[0]?.role).toBe("none");
    expect(updated[0]?.classification).toBe("fp");
    expect(updated[1]?.role).toBe("none");
    expect(updated[1]?.classification).toBe("fp");
  });

  it("includes sink classification hard constraints in label prompt", () => {
    const passDef = TAINT_ANALYSIS_PASSES[0];
    expect(passDef).toBeDefined();

    const candidates: TaintAnalysisCandidate[] = [
      {
        id: "sink-1",
        candidateKind: "sink_candidate",
        callable: "Sprintf",
        flowKind: "argument",
        argIndex: 0,
        receiverHint: "fmt",
        moduleHint: "fmt",
        locationFile: "main.go",
        locationLine: 10,
        snippet: "fmt.Sprintf(...)",
      },
    ];

    const prompt = __taintAnalysisLabelInternals.buildLabelPrompt(
      passDef!,
      candidates,
      "",
      null,
      "go",
      null,
      false,
    );

    expect(prompt).toContain("Sink classification constraints (hard rules):");
    expect(prompt).toContain("NOT sinks");
    expect(prompt).toContain("role=none, classification=fp");
  });

  it("summarizeLabels includes advisory header", () => {
    const labels: TaintAnalysisLabelsDocument = {
      version: "1.0.0",
      metadata: {
        run_id: "test",
        generated_at: new Date().toISOString(),
        language: "python",
        framework: null,
        model: "test-model",
        project: "test-repo",
      },
      passes: [
        {
          pass_id: 1,
          focus: "Path Traversal",
          cwes: ["022"],
          entries: [
            makePassEntry({ id: "s1", role: "source", callable: "Query" }),
            makePassEntry({ id: "s2", role: "sink", callable: "open" }),
          ],
        },
      ],
    };

    const { reviewSummary } = __taintAnalysisLabelInternals.summarizeLabels(labels, 0.55);
    expect(reviewSummary).toContain("> **Advisory only**");
    expect(reviewSummary).toContain("No pipeline stage gates on approval");
  });
});

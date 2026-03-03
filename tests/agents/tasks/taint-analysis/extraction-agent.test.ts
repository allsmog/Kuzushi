import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import path from "node:path";
import {
  hasBodyPlaceholders,
  computeCacheHash,
  readCacheIfValid,
  __taintAnalysisExtractionAgentInternals,
} from "../../../../src/agents/tasks/taint-analysis/extraction-agent.js";

const TMP_ROOT = path.join(import.meta.dirname, "..", "..", "..", ".tmp-taint-analysis-extraction-agent");

beforeEach(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
  mkdirSync(TMP_ROOT, { recursive: true });
});

afterEach(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

describe("hasBodyPlaceholders", () => {
  const GO_SOURCE_TEMPLATE = [
    "/**",
    " * @name {{QUERY_NAME}}",
    " * @description Go source extraction template.",
    " * @kind problem",
    " * @id {{QUERY_ID}}",
    " * @problem.severity recommendation",
    " */",
    "",
    "import go",
    "",
    "{{SOURCE_HANDLER_PREDICATE}}",
    "",
    "from {{SOURCE_NODE_BINDINGS}}",
    "where {{SOURCE_WHERE}}",
    "select {{SOURCE_SELECT}}",
  ].join("\n");

  const GO_SINK_TEMPLATE = [
    "/**",
    " * @name {{QUERY_NAME}}",
    " * @description Go sink extraction template.",
    " * @kind problem",
    " * @id {{QUERY_ID}}",
    " * @problem.severity recommendation",
    " */",
    "",
    "import go",
    "",
    "{{SINK_CALL_PREDICATE}}",
    "",
    "from {{SINK_NODE_BINDINGS}}",
    "where {{SINK_WHERE}}",
    "select {{SINK_SELECT}}",
  ].join("\n");

  const PYTHON_SOURCE_TEMPLATE = [
    "/**",
    " * @name {{QUERY_NAME}}",
    " * @description Python source extraction template.",
    " * @kind problem",
    " * @id {{QUERY_ID}}",
    " * @problem.severity recommendation",
    " */",
    "",
    "import python",
    "",
    "private predicate isRouteDecoratorExpr(Expr deco) {",
    '  deco.toString().regexpMatch(".*\\\\.(get|post|put|patch|delete|route)\\\\(.*")',
    "}",
    "",
    "from Expr node, string callable",
    "where sourceCandidate(node, callable)",
    "select node, callable",
  ].join("\n");

  const GENERIC_TEMPLATE_NO_BODY_PLACEHOLDERS = [
    "/**",
    " * @name {{QUERY_NAME}}",
    " */",
    "import python",
    "from string s",
    "where s = s",
    "select s",
  ].join("\n");

  it("returns true for Go source template", () => {
    expect(hasBodyPlaceholders(GO_SOURCE_TEMPLATE, "source")).toBe(true);
  });

  it("returns true for Go sink template", () => {
    expect(hasBodyPlaceholders(GO_SINK_TEMPLATE, "sink")).toBe(true);
  });

  it("returns false for Python source template (no body placeholders)", () => {
    expect(hasBodyPlaceholders(PYTHON_SOURCE_TEMPLATE, "source")).toBe(false);
  });

  it("returns false for template with only {{QUERY_NAME}} placeholder", () => {
    expect(hasBodyPlaceholders(GENERIC_TEMPLATE_NO_BODY_PLACEHOLDERS, "source")).toBe(false);
    expect(hasBodyPlaceholders(GENERIC_TEMPLATE_NO_BODY_PLACEHOLDERS, "sink")).toBe(false);
  });

  it("correctly checks kind-specific placeholders only", () => {
    // Source template should not trigger for sink kind
    expect(hasBodyPlaceholders(GO_SOURCE_TEMPLATE, "sink")).toBe(false);
    // Sink template should not trigger for source kind
    expect(hasBodyPlaceholders(GO_SINK_TEMPLATE, "source")).toBe(false);
  });
});

describe("cache operations", () => {
  const TEMPLATE = "import go\n{{SOURCE_HANDLER_PREDICATE}}";
  const REFERENCE = "## patterns\nSome reference docs";
  const QUERY = 'import go\nfrom DataFlow::Node n\nwhere true\nselect n, "source_candidate"';

  it("round-trips: write then read returns same query data", async () => {
    const cacheDir = path.join(TMP_ROOT, "extraction");
    mkdirSync(cacheDir, { recursive: true });
    const cachePath = path.join(cacheDir, ".cache-go-source.ql");

    const hash = computeCacheHash(TEMPLATE, REFERENCE);
    const cacheContent = `// cache:${hash}\n${QUERY}`;
    writeFileSync(cachePath, cacheContent, "utf-8");

    const result = await readCacheIfValid(cachePath, hash);
    expect(result).toBe(QUERY);
  });

  it("returns null for nonexistent cache file", async () => {
    const cachePath = path.join(TMP_ROOT, "extraction", ".cache-go-source.ql");
    const hash = computeCacheHash(TEMPLATE, REFERENCE);

    const result = await readCacheIfValid(cachePath, hash);
    expect(result).toBeNull();
  });

  it("returns null when hash mismatches (stale cache)", async () => {
    const cacheDir = path.join(TMP_ROOT, "extraction");
    mkdirSync(cacheDir, { recursive: true });
    const cachePath = path.join(cacheDir, ".cache-go-source.ql");

    const staleHash = computeCacheHash("old template", "old reference");
    const cacheContent = `// cache:${staleHash}\n${QUERY}`;
    writeFileSync(cachePath, cacheContent, "utf-8");

    const currentHash = computeCacheHash(TEMPLATE, REFERENCE);
    const result = await readCacheIfValid(cachePath, currentHash);
    expect(result).toBeNull();
  });

  it("produces deterministic hashes", () => {
    const hash1 = computeCacheHash(TEMPLATE, REFERENCE);
    const hash2 = computeCacheHash(TEMPLATE, REFERENCE);
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(16);
  });

  it("produces different hashes for different inputs", () => {
    const hash1 = computeCacheHash(TEMPLATE, REFERENCE);
    const hash2 = computeCacheHash(TEMPLATE + " modified", REFERENCE);
    expect(hash1).not.toBe(hash2);
  });
});

describe("extractQueryFromResult", () => {
  it("prefers a fenced CodeQL block over non-query fences", () => {
    const text = [
      "Generated query:",
      "```bash",
      "echo hello",
      "```",
      "",
      "```ql",
      "import go",
      "from string marker",
      "where marker = marker",
      "select marker",
      "```",
    ].join("\n");

    const query = __taintAnalysisExtractionAgentInternals.extractQueryFromResult(text);
    expect(query).toContain("import go");
    expect(query).toContain("select marker");
  });

  it("extracts query from plain text output when no fences exist", () => {
    const text = [
      "Here is the final query:",
      "/**",
      " * @name Plain Query",
      " * @kind problem",
      " */",
      "import python",
      "from string marker",
      "where marker = marker",
      "select marker",
      "",
      "This query should compile.",
    ].join("\n");

    const query = __taintAnalysisExtractionAgentInternals.extractQueryFromResult(text);
    expect(query).toContain("import python");
    expect(query).toContain("select marker");
    expect(query).not.toContain("This query should compile.");
  });

  it("returns null when no query-like content exists", () => {
    const text = "No query available. Could not generate candidate.";
    const query = __taintAnalysisExtractionAgentInternals.extractQueryFromResult(text);
    expect(query).toBeNull();
  });

  it("keeps multi-line select clauses with string literals when no trailing blank line exists", () => {
    const text = [
      "/**",
      " * @name Multi-line Select Query",
      " * @kind problem",
      " */",
      "import go",
      "from string marker",
      "where marker = marker",
      "select",
      "  marker,",
      "  \"source_candidate\",",
      "  \"callable\"",
    ].join("\n");

    const query = __taintAnalysisExtractionAgentInternals.extractQueryFromResult(text);
    expect(query).toContain("select");
    expect(query).toContain("\"source_candidate\",");
    expect(query).toContain("\"callable\"");
  });
});

describe("isAllowedCodeqlCompileCommand", () => {
  it("allows exactly the expected compile command", () => {
    const repoRoot = TMP_ROOT;
    const queryPath = path.join(TMP_ROOT, "iris", "extraction", "sources.ql");
    const workspaceDir = path.join(TMP_ROOT, "iris");
    const codeqlBinary = "/usr/local/bin/codeql";
    const command = `${codeqlBinary} query compile ${queryPath} --search-path ${workspaceDir}`;

    const allowed = __taintAnalysisExtractionAgentInternals.isAllowedCodeqlCompileCommand(command, {
      repoRoot,
      codeqlBinary,
      queryPath,
      workspaceDir,
    });

    expect(allowed).toBe(true);
  });

  it("rejects command chaining and shell metacharacters", () => {
    const repoRoot = TMP_ROOT;
    const queryPath = path.join(TMP_ROOT, "iris", "extraction", "sources.ql");
    const workspaceDir = path.join(TMP_ROOT, "iris");
    const codeqlBinary = "/usr/local/bin/codeql";
    const command = `${codeqlBinary} query compile ${queryPath} --search-path ${workspaceDir} && rm -rf /`;

    const allowed = __taintAnalysisExtractionAgentInternals.isAllowedCodeqlCompileCommand(command, {
      repoRoot,
      codeqlBinary,
      queryPath,
      workspaceDir,
    });

    expect(allowed).toBe(false);
  });

  it("rejects compile commands for a different query path", () => {
    const repoRoot = TMP_ROOT;
    const queryPath = path.join(TMP_ROOT, "iris", "extraction", "sources.ql");
    const workspaceDir = path.join(TMP_ROOT, "iris");
    const codeqlBinary = "/usr/local/bin/codeql";
    const command = `${codeqlBinary} query compile ${path.join(TMP_ROOT, "other.ql")} --search-path ${workspaceDir}`;

    const allowed = __taintAnalysisExtractionAgentInternals.isAllowedCodeqlCompileCommand(command, {
      repoRoot,
      codeqlBinary,
      queryPath,
      workspaceDir,
    });

    expect(allowed).toBe(false);
  });

  it("allows --search-path=<value> command form", () => {
    const repoRoot = TMP_ROOT;
    const queryPath = path.join(TMP_ROOT, "iris", "extraction", "sources.ql");
    const workspaceDir = path.join(TMP_ROOT, "iris");
    const codeqlBinary = "/usr/local/bin/codeql";
    const command = `${codeqlBinary} query compile ${queryPath} --search-path=${workspaceDir}`;

    const allowed = __taintAnalysisExtractionAgentInternals.isAllowedCodeqlCompileCommand(command, {
      repoRoot,
      codeqlBinary,
      queryPath,
      workspaceDir,
    });

    expect(allowed).toBe(true);
  });
});

describe("splitShellWords", () => {
  it("treats backslashes as literal characters inside single quotes", () => {
    const words = __taintAnalysisExtractionAgentInternals.splitShellWords(
      "codeql query compile '/tmp/a\\b.ql' --search-path '/tmp/w\\s'",
    );

    expect(words).toEqual([
      "codeql",
      "query",
      "compile",
      "/tmp/a\\b.ql",
      "--search-path",
      "/tmp/w\\s",
    ]);
  });
});

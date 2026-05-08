import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { executeTool } from "../../src/agent-runtime/tools.js";

const tempDirs: string[] = [];

function makeTempWorkspace(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-tools-test-"));
  tempDirs.push(dir);
  mkdirSync(path.join(dir, "src"), { recursive: true });
  mkdirSync(path.join(dir, "scripts"), { recursive: true });
  writeFileSync(
    path.join(dir, "src", "app.ts"),
    ["export function a() {", "  // TODO: sanitize input", "  return 1;", "}"].join("\n"),
    "utf8",
  );
  writeFileSync(
    path.join(dir, "scripts", "util.ts"),
    ["export const util = true;", "// TODO: tighten validation"].join("\n"),
    "utf8",
  );
  writeFileSync(path.join(dir, "README.md"), "hello", "utf8");
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("agent-runtime tools", () => {
  it("Read returns line-numbered slices", async () => {
    const cwd = makeTempWorkspace();
    const output = await executeTool(
      "Read",
      {
        path: "src/app.ts",
        offset: 1,
        limit: 2,
      },
      cwd,
    );

    expect(output).toContain("2 |   // TODO: sanitize input");
    expect(output).toContain("3 |   return 1;");
    expect(output).not.toContain("1 | export function a()");
  });

  it("Glob matches files from the selected root", async () => {
    const cwd = makeTempWorkspace();
    const output = await executeTool(
      "Glob",
      {
        pattern: "**/*.ts",
        path: "src",
      },
      cwd,
    );

    expect(output).toContain("src/app.ts");
    expect(output).not.toContain("scripts/util.ts");
  });

  it("Glob respects exclude patterns", async () => {
    const cwd = makeTempWorkspace();
    const output = await executeTool(
      "Glob",
      {
        pattern: "**/*.ts",
        exclude: ["scripts/**"],
      },
      cwd,
    );

    expect(output).toContain("src/app.ts");
    expect(output).not.toContain("scripts/util.ts");
  });

  it("Glob keeps literal directory patterns compact", async () => {
    const cwd = makeTempWorkspace();
    const output = await executeTool(
      "Glob",
      {
        pattern: ".",
      },
      cwd,
    );

    expect(output).toBe(".");
  });

  it("Glob does not emit Node experimental glob warnings", async () => {
    const cwd = makeTempWorkspace();
    const warnings: Error[] = [];
    const onWarning = (warning: Error) => {
      warnings.push(warning);
    };
    process.on("warning", onWarning);
    try {
      await executeTool(
        "Glob",
        {
          pattern: "**/*.ts",
        },
        cwd,
      );
      await Promise.resolve();
    } finally {
      process.off("warning", onWarning);
    }

    expect(
      warnings.filter(
        (warning) =>
          warning.name === "ExperimentalWarning" &&
          /\b(?:glob|matchesGlob)\b/i.test(warning.message),
      ),
    ).toEqual([]);
  });

  it("Grep returns file:line:content matches", async () => {
    const cwd = makeTempWorkspace();
    const output = await executeTool(
      "Grep",
      {
        pattern: "TODO",
        glob: "**/*.ts",
      },
      cwd,
    );

    expect(output).toContain("src/app.ts:2:  // TODO: sanitize input");
    expect(output).toContain("scripts/util.ts:2:// TODO: tighten validation");
  });

  it("Grep ignores node_modules by default", async () => {
    const cwd = makeTempWorkspace();
    mkdirSync(path.join(cwd, "node_modules", "demo"), { recursive: true });
    writeFileSync(
      path.join(cwd, "node_modules", "demo", "index.ts"),
      "// TODO: should stay hidden",
      "utf8",
    );

    const output = await executeTool(
      "Grep",
      {
        pattern: "TODO",
        glob: "**/*.ts",
      },
      cwd,
    );

    expect(output).toContain("src/app.ts:2:  // TODO: sanitize input");
    expect(output).toContain("scripts/util.ts:2:// TODO: tighten validation");
    expect(output).not.toContain("node_modules/demo/index.ts");
  });

  it("throws for unsupported tool names", async () => {
    const cwd = makeTempWorkspace();
    await expect(executeTool("Unknown", {}, cwd)).rejects.toThrow("Unsupported tool");
  });

  it("rejects paths that escape the workspace root", async () => {
    const cwd = makeTempWorkspace();
    const outsidePath = path.resolve(cwd, "..", "outside.txt");

    await expect(
      executeTool(
        "Read",
        {
          path: outsidePath,
        },
        cwd,
      ),
    ).rejects.toThrow("Path escapes repository root");

    await expect(
      executeTool(
        "Read",
        {
          path: "../outside.txt",
        },
        cwd,
      ),
    ).rejects.toThrow("Path escapes repository root");
  });
});

function makeCrossProceduralWorkspace(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-xproc-test-"));
  tempDirs.push(dir);
  mkdirSync(path.join(dir, "src"), { recursive: true });
  mkdirSync(path.join(dir, "lib"), { recursive: true });

  writeFileSync(
    path.join(dir, "src", "handler.ts"),
    [
      "import { sanitize } from '../lib/sanitize';",
      "import { db } from '../lib/db';",
      "",
      "export function handleRequest(req: Request) {",
      "  const input = sanitize(req.body);",
      "  const result = db.query(input);",
      "  return formatResponse(result);",
      "}",
      "",
      "function formatResponse(data: unknown) {",
      "  return JSON.stringify(data);",
      "}",
    ].join("\n"),
    "utf8",
  );

  writeFileSync(
    path.join(dir, "lib", "sanitize.ts"),
    [
      "export function sanitize(input: string): string {",
      "  return input.replace(/[<>]/g, '');",
      "}",
    ].join("\n"),
    "utf8",
  );

  writeFileSync(
    path.join(dir, "lib", "db.ts"),
    [
      "export const db = {",
      "  query(sql: string) {",
      "    return executeQuery(sql);",
      "  }",
      "};",
      "",
      "function executeQuery(sql: string) {",
      "  return sql;",
      "}",
    ].join("\n"),
    "utf8",
  );

  writeFileSync(
    path.join(dir, "src", "routes.ts"),
    [
      "import { handleRequest } from './handler';",
      "",
      "export function setupRoutes(app: any) {",
      "  app.post('/api', (req: any) => handleRequest(req));",
      "  app.get('/health', () => 'ok');",
      "}",
    ].join("\n"),
    "utf8",
  );

  writeFileSync(
    path.join(dir, "src", "app.py"),
    [
      "def process_input(data):",
      "    cleaned = sanitize_input(data)",
      "    return run_query(cleaned)",
      "",
      "def sanitize_input(raw):",
      "    return raw.strip()",
      "",
      "class UserService:",
      "    def get_user(self, user_id):",
      "        return self.db.find(user_id)",
    ].join("\n"),
    "utf8",
  );

  writeFileSync(
    path.join(dir, "src", "main.go"),
    [
      "package main",
      "",
      "func HandleHTTP(w http.ResponseWriter, r *http.Request) {",
      "    body := parseBody(r)",
      "    result := processData(body)",
      "    writeResponse(w, result)",
      "}",
      "",
      "func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {",
      "    HandleHTTP(w, r)",
      "}",
    ].join("\n"),
    "utf8",
  );

  return dir;
}

function makeSemanticWorkspace(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-semantic-test-"));
  tempDirs.push(dir);
  mkdirSync(path.join(dir, "src"), { recursive: true });

  writeFileSync(
    path.join(dir, "tsconfig.json"),
    JSON.stringify(
      {
        compilerOptions: {
          target: "ES2020",
          module: "ESNext",
          moduleResolution: "Node",
          strict: true,
        },
        include: ["src/**/*.ts"],
      },
      null,
      2,
    ),
    "utf8",
  );

  writeFileSync(
    path.join(dir, "src", "dep.ts"),
    ["export function greet(name: string): string {", "  return `hi ${name}`;", "}"].join("\n"),
    "utf8",
  );

  writeFileSync(
    path.join(dir, "src", "main.ts"),
    [
      "import { greet } from './dep';",
      "",
      "const userId = 'guest';",
      "const message = greet(userId);",
      "const label = 'greet';",
      "// greet in comment should not count as a reference",
      "console.log(message, label);",
    ].join("\n"),
    "utf8",
  );

  writeFileSync(
    path.join(dir, "src", "worker.py"),
    ["def greet(name):", "    return f'hi {name}'"].join("\n"),
    "utf8",
  );

  return dir;
}

describe("GetFunctionBody", () => {
  it("finds JS/TS function declarations", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetFunctionBody",
      {
        name: "handleRequest",
        file_path: "src/handler.ts",
      },
      cwd,
    );

    expect(output).toContain("src/handler.ts:4");
    expect(output).toContain("export function handleRequest");
    expect(output).toContain("sanitize(req.body)");
    expect(output).toContain("formatResponse(result)");
  });

  it("finds Python def declarations", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetFunctionBody",
      {
        name: "process_input",
        file_path: "src/app.py",
      },
      cwd,
    );

    expect(output).toContain("src/app.py:1");
    expect(output).toContain("def process_input");
    expect(output).toContain("sanitize_input(data)");
  });

  it("finds Go func declarations", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetFunctionBody",
      {
        name: "HandleHTTP",
        file_path: "src/main.go",
      },
      cwd,
    );

    expect(output).toContain("src/main.go:3");
    expect(output).toContain("func HandleHTTP");
    expect(output).toContain("parseBody(r)");
  });

  it("searches the entire repo when file_path is omitted", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetFunctionBody",
      {
        name: "sanitize",
      },
      cwd,
    );

    expect(output).toContain("lib/sanitize.ts");
    expect(output).toContain("function sanitize");
  });

  it("returns not found for nonexistent function", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetFunctionBody",
      {
        name: "doesNotExist",
        file_path: "src/handler.ts",
      },
      cwd,
    );

    expect(output).toContain("not found");
  });

  it("throws for missing file", async () => {
    const cwd = makeCrossProceduralWorkspace();
    await expect(
      executeTool(
        "GetFunctionBody",
        {
          name: "foo",
          file_path: "nonexistent.ts",
        },
        cwd,
      ),
    ).rejects.toThrow("file not found");
  });

  it("finds Go receiver method declarations", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetFunctionBody",
      {
        name: "ServeHTTP",
        file_path: "src/main.go",
        language: "go",
      },
      cwd,
    );

    expect(output).toContain("src/main.go");
    expect(output).toContain("ServeHTTP");
  });

  it("finds Python class declarations", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetFunctionBody",
      {
        name: "UserService",
        file_path: "src/app.py",
        language: "py",
      },
      cwd,
    );

    expect(output).toContain("class UserService");
  });
});

describe("GetCallers", () => {
  it("finds call sites across the codebase", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetCallers",
      {
        name: "handleRequest",
      },
      cwd,
    );

    expect(output).toContain("src/routes.ts");
    expect(output).toContain("handleRequest");
    // Should NOT include the definition itself
    expect(output).not.toContain("export function handleRequest");
  });

  it("finds call sites for sanitize", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetCallers",
      {
        name: "sanitize",
      },
      cwd,
    );

    expect(output).toContain("src/handler.ts");
    expect(output).toContain("sanitize(req.body)");
  });

  it("respects max_results", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetCallers",
      {
        name: "sanitize",
        max_results: 1,
      },
      cwd,
    );

    const lines = output.split("\n").filter(Boolean);
    // At most 1 result line + possible truncation message
    expect(lines.length).toBeLessThanOrEqual(2);
  });

  it("scopes search to a directory", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetCallers",
      {
        name: "handleRequest",
        path: "lib",
      },
      cwd,
    );

    expect(output).toContain("No callers found");
  });

  it("returns no callers for unused function", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetCallers",
      {
        name: "formatResponse",
      },
      cwd,
    );

    // formatResponse is called inside handleRequest
    expect(output).toContain("src/handler.ts");
  });
});

describe("GetCallees", () => {
  it("extracts function calls from a function body", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetCallees",
      {
        name: "handleRequest",
        file_path: "src/handler.ts",
      },
      cwd,
    );

    expect(output).toContain("sanitize");
    expect(output).toContain("formatResponse");
  });

  it("extracts method calls", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetCallees",
      {
        name: "handleRequest",
        file_path: "src/handler.ts",
      },
      cwd,
    );

    expect(output).toContain("query");
  });

  it("filters out language keywords", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetCallees",
      {
        name: "handleRequest",
        file_path: "src/handler.ts",
      },
      cwd,
    );

    expect(output).not.toContain("return");
    expect(output).not.toContain("import");
  });

  it("deduplicates callees", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetCallees",
      {
        name: "handleRequest",
        file_path: "src/handler.ts",
      },
      cwd,
    );

    const callees = output.split("\n").filter(Boolean);
    const unique = new Set(callees);
    expect(callees.length).toBe(unique.size);
  });

  it("returns not found for nonexistent function", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetCallees",
      {
        name: "doesNotExist",
        file_path: "src/handler.ts",
      },
      cwd,
    );

    expect(output).toContain("not found");
  });

  it("requires file_path", async () => {
    const cwd = makeCrossProceduralWorkspace();
    await expect(
      executeTool(
        "GetCallees",
        {
          name: "handleRequest",
        },
        cwd,
      ),
    ).rejects.toThrow("requires a file_path");
  });

  it("extracts callees from Python function", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetCallees",
      {
        name: "process_input",
        file_path: "src/app.py",
      },
      cwd,
    );

    expect(output).toContain("sanitize_input");
    expect(output).toContain("run_query");
  });

  it("returns no callees for a function with no calls", async () => {
    const cwd = makeCrossProceduralWorkspace();
    const output = await executeTool(
      "GetCallees",
      {
        name: "sanitize",
        file_path: "lib/sanitize.ts",
      },
      cwd,
    );

    // sanitize only calls .replace() which is a method call
    expect(output).toContain("replace");
  });

  it("does not bleed callees from the next function in the same file", async () => {
    const cwd = makeCrossProceduralWorkspace();
    // handleRequest ends before formatResponse starts.
    // formatResponse calls JSON.stringify — that should NOT appear in handleRequest's callees
    const output = await executeTool(
      "GetCallees",
      {
        name: "handleRequest",
        file_path: "src/handler.ts",
      },
      cwd,
    );

    expect(output).not.toContain("stringify");
  });

  it("excludes recursive self-calls from callees", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-xproc-recurse-"));
    tempDirs.push(dir);
    writeFileSync(
      path.join(dir, "recurse.ts"),
      [
        "function factorial(n: number): number {",
        "  if (n <= 1) return 1;",
        "  return n * factorial(n - 1);",
        "}",
        "",
        "function helper(x: number) {",
        "  return factorial(x) + compute(x);",
        "}",
      ].join("\n"),
      "utf8",
    );
    const output = await executeTool(
      "GetCallees",
      {
        name: "factorial",
        file_path: "recurse.ts",
      },
      dir,
    );

    // factorial calls itself recursively — self-call should be excluded
    // but the output should list callees as individual lines, not contain "factorial" as a callee line
    const calleeLines = output.split("\n").filter(Boolean);
    expect(calleeLines).not.toContain("factorial");
  });
});

describe("Cross-procedural tools - regression tests", () => {
  it("GetCallers does not filter out line-start call sites as definitions", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-xproc-callsite-"));
    tempDirs.push(dir);
    writeFileSync(
      path.join(dir, "caller.ts"),
      [
        "import { doWork } from './work';",
        "",
        "// top-level call at start of line",
        "doWork(42);",
      ].join("\n"),
      "utf8",
    );
    writeFileSync(
      path.join(dir, "work.ts"),
      ["export function doWork(n: number) {", "  return n * 2;", "}"].join("\n"),
      "utf8",
    );
    const output = await executeTool(
      "GetCallers",
      {
        name: "doWork",
      },
      dir,
    );

    // The line-start call "doWork(42);" must appear as a caller, not be filtered as a definition
    expect(output).toContain("caller.ts");
    expect(output).toContain("doWork(42)");
  });

  it("GetFunctionBody and GetCallers reject paths escaping the workspace", async () => {
    const cwd = makeCrossProceduralWorkspace();

    await expect(
      executeTool(
        "GetFunctionBody",
        {
          name: "foo",
          file_path: "../outside.ts",
        },
        cwd,
      ),
    ).rejects.toThrow("Path escapes repository root");

    await expect(
      executeTool(
        "GetCallers",
        {
          name: "foo",
          path: "../outside",
        },
        cwd,
      ),
    ).rejects.toThrow("Path escapes repository root");

    await expect(
      executeTool(
        "GetCallees",
        {
          name: "foo",
          file_path: "../outside.ts",
        },
        cwd,
      ),
    ).rejects.toThrow("Path escapes repository root");
  });

  it("handles function names with regex special characters ($apply)", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-xproc-special-"));
    tempDirs.push(dir);
    writeFileSync(
      path.join(dir, "special.ts"),
      [
        "function $apply(scope: any) {",
        "  return evalScope(scope);",
        "}",
        "",
        "const result = $apply(myScope);",
      ].join("\n"),
      "utf8",
    );

    const body = await executeTool(
      "GetFunctionBody",
      {
        name: "$apply",
        file_path: "special.ts",
      },
      dir,
    );
    expect(body).toContain("function $apply");

    const callers = await executeTool(
      "GetCallers",
      {
        name: "$apply",
      },
      dir,
    );
    expect(callers).toContain("$apply(myScope)");

    const callees = await executeTool(
      "GetCallees",
      {
        name: "$apply",
        file_path: "special.ts",
      },
      dir,
    );
    expect(callees).toContain("evalScope");
  });

  it("handles empty files gracefully", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-xproc-empty-"));
    tempDirs.push(dir);
    writeFileSync(path.join(dir, "empty.ts"), "", "utf8");

    const body = await executeTool(
      "GetFunctionBody",
      {
        name: "foo",
        file_path: "empty.ts",
      },
      dir,
    );
    expect(body).toContain("not found");

    const callees = await executeTool(
      "GetCallees",
      {
        name: "foo",
        file_path: "empty.ts",
      },
      dir,
    );
    expect(callees).toContain("not found");
  });
});

describe("Semantic navigation tools", () => {
  it("GoToDefinition resolves cross-file TypeScript imports", async () => {
    const cwd = makeSemanticWorkspace();
    const output = await executeTool(
      "GoToDefinition",
      {
        file_path: "src/main.ts",
        line: 4,
        column: 18,
      },
      cwd,
    );

    expect(output).toContain("Symbol: greet");
    expect(output).toContain("src/dep.ts:1:17:export function greet(name: string): string {");
  }, 70_000);

  it("FindReferences returns symbol references, not pure text matches", async () => {
    const cwd = makeSemanticWorkspace();
    const output = await executeTool(
      "FindReferences",
      {
        file_path: "src/main.ts",
        line: 4,
        column: 17,
      },
      cwd,
    );

    expect(output).toContain("src/main.ts:1:10:import { greet } from './dep';");
    expect(output).toContain("src/main.ts:4:17:const message = greet(userId);");
    expect(output).not.toContain("src/main.ts:5");
    expect(output).not.toContain("src/main.ts:6");
  }, 70_000);

  it("TypeAtPosition returns the inferred type for a local variable", async () => {
    const cwd = makeSemanticWorkspace();
    const output = await executeTool(
      "TypeAtPosition",
      {
        file_path: "src/main.ts",
        line: 4,
        column: 7,
      },
      cwd,
    );

    expect(output).toContain("Symbol: message");
    expect(output).toContain("Kind: const");
    expect(output).toContain("Type:");
    expect(output).toContain("string");
    expect(output).toContain("Location: src/main.ts:4:7");
  }, 70_000);

  it("returns a stable message for unsupported file types", async () => {
    const cwd = makeSemanticWorkspace();
    const output = await executeTool(
      "TypeAtPosition",
      {
        file_path: "src/worker.py",
        line: 1,
        column: 5,
      },
      cwd,
    );

    expect(output).toContain(
      "Semantic navigation is only supported for TypeScript/JavaScript files",
    );
    expect(output).toContain("src/worker.py");
  });

  it("rejects workspace escapes for semantic navigation tools", async () => {
    const cwd = makeSemanticWorkspace();

    await expect(
      executeTool(
        "GoToDefinition",
        {
          file_path: "../outside.ts",
          line: 1,
          column: 1,
        },
        cwd,
      ),
    ).rejects.toThrow("Path escapes repository root");
  });
});

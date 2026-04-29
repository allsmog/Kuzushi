import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ChromeRcePlugin, createChromeRceModule } from "../../src/modules/chrome-rce/chrome-rce.js";
import {
  RULE_ID as MOJO_PSEUDOHANDLE_RULE_ID,
  MOJO_PSEUDOHANDLE_YAML,
} from "../../src/modules/chrome-rce/rules/mojo-pseudohandle.js";
import { reviewTriggerDagTool } from "../../src/modules/chrome-rce/rules/review-trigger.js";
import type { ExecutionContext } from "../../src/modules/types.js";

// Mock the semgrep binary resolver so the test never tries to execute the
// actual semgrep CLI; the e2e variant below uses a fake shell script.
vi.mock("../../src/scanners/resolve-semgrep.js", () => ({
  resolveSemgrepBinary: vi.fn().mockResolvedValue("/usr/bin/echo-not-real-semgrep"),
}));

// Mock runSemgrep so we can drive the conversion pipeline with synthetic
// JSON output without spawning a real subprocess.
const runSemgrepMock = vi.fn();
vi.mock("../../src/scanners/run-semgrep.js", async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    runSemgrep: (...args: unknown[]) => runSemgrepMock(...args),
  };
});

describe("createChromeRceModule", () => {
  it("returns a module with the expected shape and the V1 tool surface", () => {
    const mod = createChromeRceModule();
    expect(mod.id).toBe("chrome-rce");
    expect(mod.version).toBe("0.1.0");
    expect(mod.category).toBe("defense");
    expect(mod.rank).toBe("good");
    expect(mod.tools.map((t) => t.name).sort()).toEqual([
      "chrome-rce:review-trigger",
      "chrome-rce:scan",
    ]);
    for (const t of mod.tools) {
      expect(t.headless).toBe(true);
    }
  });

  it("declares the anchor CVE in references", () => {
    const mod = createChromeRceModule();
    expect(mod.references).toContainEqual({ type: "CVE", value: "CVE-2025-2783" });
  });
});

describe("MOJO_PSEUDOHANDLE_YAML", () => {
  it("includes the canonical rule id", () => {
    expect(MOJO_PSEUDOHANDLE_RULE_ID).toBe("chrome-rce-mojo-broker-pseudohandle-reject");
    expect(MOJO_PSEUDOHANDLE_YAML).toContain(`id: ${MOJO_PSEUDOHANDLE_RULE_ID}`);
  });

  it("declares languages, severity, and the anchor CVE in metadata", () => {
    expect(MOJO_PSEUDOHANDLE_YAML).toContain("severity: ERROR");
    expect(MOJO_PSEUDOHANDLE_YAML).toContain("languages: [cpp]");
    expect(MOJO_PSEUDOHANDLE_YAML).toContain("CVE-2025-2783");
  });
});

describe("ChromeRcePlugin.scan", () => {
  it("returns findings tagged with taskId=chrome-rce when semgrep matches", async () => {
    runSemgrepMock.mockReset();
    runSemgrepMock.mockResolvedValueOnce({
      results: [
        {
          check_id: "chrome-rce-mojo-broker-pseudohandle-reject",
          path: "ipc/broker_impl.cc",
          start: { line: 42, col: 5 },
          end: { line: 42, col: 80 },
          extra: {
            severity: "ERROR",
            message: "DuplicateHandle without pseudo-handle reject",
            lines:
              "  return ::DuplicateHandle(GetCurrentProcess(), renderer_handle, target_process, out_dup, 0, FALSE, DUPLICATE_SAME_ACCESS);",
            metadata: {
              cwe: ["CWE-862"],
              confidence: "HIGH",
              likelihood: "HIGH",
              impact: "HIGH",
              subcategory: ["chrome-rce", "mojo-broker"],
            },
          },
        },
      ],
    });

    const plugin = new ChromeRcePlugin();
    await plugin.init({});
    const findings = await plugin.scan(
      "/tmp/fake-repo",
      { severity: [], excludePatterns: [], fresh: false },
      {},
    );

    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.taskId).toBe("chrome-rce");
    expect(f.ruleId).toBe("chrome-rce-mojo-broker-pseudohandle-reject");
    expect(f.filePath).toBe("ipc/broker_impl.cc");
    expect(f.startLine).toBe(42);
    expect(f.cwe).toEqual(["CWE-862"]);
    expect(f.engineProvenance).toEqual([
      { kind: "semgrep", detail: "chrome-rce semgrep rule match" },
    ]);
    expect(f.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("dedupes by fingerprint and keeps the highest-scoring finding", async () => {
    // Same `path`, `lines`, and `message` → same fingerprint per
    // `computeFingerprint`. Different severity/likelihood/impact yield
    // different scores, so the dedup pass should pick the higher one.
    runSemgrepMock.mockReset();
    const sameLines =
      "  return ::DuplicateHandle(GetCurrentProcess(), renderer_handle, target_process, out_dup, 0, FALSE, DUPLICATE_SAME_ACCESS);";
    const sameMessage = "DuplicateHandle without pseudo-handle reject";
    runSemgrepMock.mockResolvedValueOnce({
      results: [
        {
          check_id: "chrome-rce-mojo-broker-pseudohandle-reject",
          path: "ipc/broker_impl.cc",
          start: { line: 42, col: 5 },
          end: { line: 42, col: 80 },
          extra: {
            severity: "WARNING",
            message: sameMessage,
            lines: sameLines,
            metadata: { confidence: "LOW", likelihood: "LOW", impact: "LOW" },
          },
        },
        {
          check_id: "chrome-rce-mojo-broker-pseudohandle-reject",
          path: "ipc/broker_impl.cc",
          start: { line: 42, col: 5 },
          end: { line: 42, col: 80 },
          extra: {
            severity: "ERROR",
            message: sameMessage,
            lines: sameLines,
            metadata: { confidence: "HIGH", likelihood: "HIGH", impact: "HIGH" },
          },
        },
      ],
    });

    const plugin = new ChromeRcePlugin();
    await plugin.init({});
    const findings = await plugin.scan(
      "/tmp/fake-repo",
      { severity: [], excludePatterns: [], fresh: false },
      {},
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("ERROR");
    expect(findings[0]!.scannerConfidence).toBe("HIGH");
  });

  it("returns an empty array when semgrep finds nothing", async () => {
    runSemgrepMock.mockReset();
    runSemgrepMock.mockResolvedValueOnce({ results: [] });

    const plugin = new ChromeRcePlugin();
    await plugin.init({});
    const findings = await plugin.scan(
      "/tmp/fake-repo",
      { severity: [], excludePatterns: [], fresh: false },
      {},
    );
    expect(findings).toEqual([]);
  });
});

describe("ChromeRcePlugin.triageAgentConfig", () => {
  it("references the chrome-rce rule pack and includes the finding metadata", () => {
    const plugin = new ChromeRcePlugin();
    const cfg = plugin.triageAgentConfig(
      {
        taskId: "chrome-rce",
        fingerprint: "deadbeef",
        ruleId: "chrome-rce-mojo-broker-pseudohandle-reject",
        filePath: "ipc/broker_impl.cc",
        startLine: 42,
        severity: "ERROR",
        message: "...",
        scannerConfidence: "HIGH",
        subcategory: ["chrome-rce"],
        likelihood: "HIGH",
        impact: "HIGH",
        cwe: ["CWE-862"],
        score: 0.9,
      },
      "chromium",
    );
    expect(cfg.prompt).toContain("Chrome-RCE-focused security triage");
    expect(cfg.prompt).toContain("chrome-rce");
    expect(cfg.prompt).toContain("ipc/broker_impl.cc:42");
    expect(cfg.prompt).toContain("CWE-862");
  });
});

describe("chrome-rce:review-trigger", () => {
  let repoDir: string;

  function git(args: string[]): string {
    return execFileSync("git", args, {
      cwd: repoDir,
      encoding: "utf-8",
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: "Test",
        GIT_AUTHOR_EMAIL: "test@example.com",
        GIT_COMMITTER_NAME: "Test",
        GIT_COMMITTER_EMAIL: "test@example.com",
      },
    });
  }

  function writeRepoFile(rel: string, contents: string): void {
    const full = path.join(repoDir, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, contents, "utf8");
  }

  function makeContext(): ExecutionContext {
    return {
      cwd: repoDir,
      runtime: { id: "test", async *query() {} },
      bus: {} as ExecutionContext["bus"],
      config: {} as ExecutionContext["config"],
      target: repoDir,
      dag: {
        runId: "test-run",
        repoRoot: repoDir,
        repoName: path.basename(repoDir),
        upstreamOutputs: new Map(),
      },
    } as ExecutionContext;
  }

  beforeEach(() => {
    repoDir = mkdtempSync(path.join(tmpdir(), "kuzushi-chrome-rce-review-"));
    git(["init", "--initial-branch=main", "--quiet"]);
    git(["config", "commit.gpgsign", "false"]);

    // Initial commit: a hot-path file + a non-hot-path file, both unchanged.
    writeRepoFile("v8/src/maglev/maglev-phi-representation-selector.cc", "// initial\n");
    writeRepoFile("v8/src/compiler/typer.cc", "// initial\n");
    writeRepoFile("third_party/dawn/src/dawn/wire/server/Server.cpp", "// initial\n");
    writeRepoFile("foo/bar.cc", "// initial\n");
    writeRepoFile("README.md", "# repo\n");
    git(["add", "."]);
    git(["commit", "-m", "initial", "--quiet"]);
  });

  afterEach(() => {
    rmSync(repoDir, { recursive: true, force: true });
  });

  it("returns no findings when diffBase is unset", async () => {
    const findings = await reviewTriggerDagTool.run(
      { severity: [], excludePatterns: [], fresh: false },
      makeContext(),
    );
    expect(findings).toEqual([]);
  });

  it("flags a changed file matching an exact-filename hot path with high severity", async () => {
    writeRepoFile(
      "v8/src/maglev/maglev-phi-representation-selector.cc",
      "// initial\n// representational change\n",
    );
    git(["add", "."]);
    git(["commit", "-m", "touch maglev-phi", "--quiet"]);

    const findings = await reviewTriggerDagTool.run(
      { severity: [], excludePatterns: [], fresh: false, diffBase: "HEAD~1" },
      makeContext(),
    );

    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.filePath).toBe("v8/src/maglev/maglev-phi-representation-selector.cc");
    expect(f.severity).toBe("HIGH");
    expect(f.ruleId).toBe("chrome-rce-hot-path-v8-maglev-phi-representation-selector");
    expect(f.subcategory).toContain("CVE-2026-3910");
    expect(f.taskId).toBe("chrome-rce");
  });

  it("flags a changed file matching a directory hot path", async () => {
    writeRepoFile(
      "third_party/dawn/src/dawn/wire/server/Server.cpp",
      "// initial\n// dispatcher change\n",
    );
    git(["add", "."]);
    git(["commit", "-m", "touch dawn server", "--quiet"]);

    const findings = await reviewTriggerDagTool.run(
      { severity: [], excludePatterns: [], fresh: false, diffBase: "HEAD~1" },
      makeContext(),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("chrome-rce-hot-path-dawn-wire-server");
    expect(findings[0]!.subcategory).toContain("CVE-2026-5281");
  });

  it("ignores changed files that are not on any hot path", async () => {
    writeRepoFile("foo/bar.cc", "// initial\n// changed\n");
    git(["add", "."]);
    git(["commit", "-m", "touch foo/bar", "--quiet"]);

    const findings = await reviewTriggerDagTool.run(
      { severity: [], excludePatterns: [], fresh: false, diffBase: "HEAD~1" },
      makeContext(),
    );
    expect(findings).toEqual([]);
  });

  it("prefers the exact-filename match over the broader directory match", async () => {
    // Both `v8/src/maglev/maglev-phi-representation-selector.cc` (exact)
    // and `v8/src/maglev/` (directory) match. Exact wins → high severity.
    writeRepoFile("v8/src/maglev/maglev-phi-representation-selector.cc", "// initial\n// edit\n");
    git(["add", "."]);
    git(["commit", "-m", "edit maglev-phi", "--quiet"]);

    const findings = await reviewTriggerDagTool.run(
      { severity: [], excludePatterns: [], fresh: false, diffBase: "HEAD~1" },
      makeContext(),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("chrome-rce-hot-path-v8-maglev-phi-representation-selector");
    expect(findings[0]!.severity).toBe("HIGH");
  });

  it("returns an empty array when diffBase ref does not exist", async () => {
    const findings = await reviewTriggerDagTool.run(
      { severity: [], excludePatterns: [], fresh: false, diffBase: "no-such-branch" },
      makeContext(),
    );
    expect(findings).toEqual([]);
  });
});

describe("chrome-rce content packs", () => {
  const moduleDir = path.resolve(__dirname, "..", "..", "src", "modules", "chrome-rce");

  it("ships the Dawn server stale-pointer hunt prompt with anchor CVEs", () => {
    const file = path.join(moduleDir, "hunt-prompts", "dawn-server-stale-pointer.md");
    expect(existsSync(file)).toBe(true);
    const text = readFileSync(file, "utf8");
    expect(text).toContain("CVE-2026-4676");
    expect(text).toContain("CVE-2026-5281");
    expect(text).toContain("Dawn");
    expect(text).toContain("objects_.Get");
  });

  it("ships the Mojo receiver UAF hunt prompt with anchor CVE", () => {
    const file = path.join(moduleDir, "hunt-prompts", "mojo-receiver-uaf.md");
    expect(existsSync(file)).toBe(true);
    const text = readFileSync(file, "utf8");
    expect(text).toContain("CVE-2024-4671");
    expect(text).toContain("mojo::Receiver");
    expect(text).toContain("WeakMember");
  });

  it("ships the libwebp codec IRIS seed with anchor CVE", () => {
    const file = path.join(moduleDir, "iris-seeds", "codec-fixed-table-vs-format-spec.md");
    expect(existsSync(file)).toBe(true);
    const text = readFileSync(file, "utf8");
    expect(text).toContain("CVE-2023-4863");
    expect(text).toContain("BuildHuffmanTable");
    expect(text).toContain("CodeQL");
  });

  it("ships the libvpx codec IRIS seed with anchor CVE", () => {
    const file = path.join(moduleDir, "iris-seeds", "codec-config-overwrite-after-init.md");
    expect(existsSync(file)).toBe(true);
    const text = readFileSync(file, "utf8");
    expect(text).toContain("CVE-2023-5217");
    expect(text).toContain("multi_threaded");
    expect(text).toContain("CodeQL");
  });
});

// Optional end-to-end smoke: only runs when RUN_SEMGREP_E2E=1 and a real
// semgrep is on PATH. Kept here so the rule's pattern can be regression-
// tested against the fixture tree without making CI depend on semgrep.
if (process.env["RUN_SEMGREP_E2E"] === "1") {
  describe("ChromeRcePlugin.scan e2e (real semgrep)", () => {
    it("fires on the positive fixture and is silent on the negative one", async () => {
      const root = path.resolve(__dirname, "..", "fixtures", "chrome-rce", "mojo-pseudohandle");

      // Allow override of binary path for sandboxed CI.
      const binary = process.env["KUZUSHI_SEMGREP_BIN"] ?? "semgrep";
      process.env["KUZUSHI_SEMGREP_BIN"] = binary;

      const plugin = new ChromeRcePlugin();
      await plugin.init({ binary });
      const findings = await plugin.scan(
        root,
        { severity: [], excludePatterns: [], fresh: false },
        {},
      );

      const positives = findings.filter((f) => f.filePath.includes("/positive/"));
      const negatives = findings.filter((f) => f.filePath.includes("/negative/"));
      expect(positives.length).toBeGreaterThan(0);
      expect(negatives.length).toBe(0);
    });
  });
}

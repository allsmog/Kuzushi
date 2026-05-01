import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  buildReproducibility,
  canonicalJson,
  countFindingsBy,
  hashConfig,
  RUN_SUMMARY_FILENAME,
  RUN_SUMMARY_SCHEMA_VERSION,
  readEnvFingerprint,
  readHouseRulesFingerprints,
  readPromptOverrideFingerprints,
  readRunSummary,
  readThreatModelDigest,
  sha256,
} from "../../src/copilot/run-metadata.js";
import type { KuzushiConfig, ScanOpts } from "../../src/types.js";

function mkConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: { semgrep: {} },
    ...overrides,
  } as KuzushiConfig;
}

function mkScanOpts(): ScanOpts {
  return {
    severity: ["ERROR"],
    excludePatterns: [],
    tasks: ["semgrep"],
    fresh: false,
  } as ScanOpts;
}

describe("run-metadata", () => {
  let dataDir: string;

  beforeEach(() => {
    dataDir = path.join(tmpdir(), `kuzushi-run-metadata-test-${Date.now()}-${Math.random()}`);
    mkdirSync(dataDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  describe("canonicalJson + sha256", () => {
    it("produces stable output regardless of key order", () => {
      const a = canonicalJson({ b: 1, a: 2, c: { y: 3, x: 4 } });
      const b = canonicalJson({ a: 2, c: { x: 4, y: 3 }, b: 1 });
      expect(a).toBe(b);
    });

    it("sha256 is deterministic", () => {
      expect(sha256("hello")).toBe(sha256("hello"));
      expect(sha256("hello")).not.toBe(sha256("world"));
    });
  });

  describe("hashConfig", () => {
    it("yields the same hash for two configs that differ only in key order", () => {
      const c1 = mkConfig();
      const c2 = mkConfig();
      expect(hashConfig(c1)).toBe(hashConfig(c2));
      expect(hashConfig(c1)).toMatch(/^sha256:[0-9a-f]{64}$/);
    });

    it("changes when a meaningful field changes", () => {
      const c1 = mkConfig();
      const c2 = mkConfig({ model: "anthropic:claude-opus-4-7" });
      expect(hashConfig(c1)).not.toBe(hashConfig(c2));
    });
  });

  describe("readEnvFingerprint", () => {
    it("includes KUZUSHI_* vars and presence-only API keys", () => {
      const env = {
        KUZUSHI_DEBUG: "1",
        ANTHROPIC_API_KEY: "sk-secret-shhhhh",
        UNRELATED: "value",
      };
      const fp = readEnvFingerprint(env as NodeJS.ProcessEnv);
      expect(fp.KUZUSHI_DEBUG).toBe("1");
      expect(fp.ANTHROPIC_API_KEY).toBe("<set>");
      expect(fp.UNRELATED).toBeUndefined();
    });

    it("truncates very long KUZUSHI_* values", () => {
      const long = "x".repeat(200);
      const env = { KUZUSHI_LONG: long };
      const fp = readEnvFingerprint(env as NodeJS.ProcessEnv);
      expect(fp.KUZUSHI_LONG!.length).toBeLessThan(long.length);
      expect(fp.KUZUSHI_LONG!.endsWith("...")).toBe(true);
    });

    it("ignores empty/undefined env values", () => {
      const env = { KUZUSHI_EMPTY: "", KUZUSHI_OK: "y" };
      const fp = readEnvFingerprint(env as NodeJS.ProcessEnv);
      expect(fp.KUZUSHI_EMPTY).toBeUndefined();
      expect(fp.KUZUSHI_OK).toBe("y");
    });
  });

  describe("prompt + house-rules fingerprints", () => {
    it("hashes every prompt override file, sorted by (module, verb)", () => {
      mkdirSync(path.join(dataDir, "prompts", "core-sast"), { recursive: true });
      mkdirSync(path.join(dataDir, "prompts", "randori"), { recursive: true });
      writeFileSync(path.join(dataDir, "prompts", "core-sast", "triage.md"), "BODY-TRIAGE");
      writeFileSync(path.join(dataDir, "prompts", "randori", "model.md"), "BODY-MODEL");
      writeFileSync(path.join(dataDir, "prompts", "core-sast", "ignore.txt"), "skip me");

      const out = readPromptOverrideFingerprints(dataDir);
      expect(out).toHaveLength(2);
      expect(out[0]).toEqual({
        module: "core-sast",
        verb: "triage",
        sha256: sha256("BODY-TRIAGE"),
      });
      expect(out[1]).toEqual({
        module: "randori",
        verb: "model",
        sha256: sha256("BODY-MODEL"),
      });
    });

    it("returns empty array when prompts dir is missing", () => {
      expect(readPromptOverrideFingerprints(dataDir)).toEqual([]);
    });

    it("hashes house-rules markdown files by module id", () => {
      mkdirSync(path.join(dataDir, "house-rules"), { recursive: true });
      writeFileSync(path.join(dataDir, "house-rules", "randori.md"), "RULES");
      writeFileSync(path.join(dataDir, "house-rules", "core-sast.md"), "RULES2");
      const out = readHouseRulesFingerprints(dataDir);
      expect(out).toHaveLength(2);
      expect(out.find((r) => r.module === "randori")?.sha256).toBe(sha256("RULES"));
    });

    it("digests the threat-model file when present", () => {
      const file = path.join(dataDir, "threat-model.json");
      writeFileSync(file, '{"a":1}');
      expect(readThreatModelDigest(dataDir)).toBe(sha256('{"a":1}'));
      rmSync(file);
      expect(readThreatModelDigest(dataDir)).toBeUndefined();
    });
  });

  describe("buildReproducibility", () => {
    it("composes a full repro blob from disk + config", () => {
      mkdirSync(path.join(dataDir, "prompts", "core-sast"), { recursive: true });
      writeFileSync(path.join(dataDir, "prompts", "core-sast", "triage.md"), "BODY");
      const config = mkConfig({});
      const repro = buildReproducibility({
        config,
        scanOpts: mkScanOpts(),
        repoRoot: dataDir, // not a git repo, git block stays undefined
        dataDir,
        argv: ["scan", "./repo", "--preset", "deep"],
        env: { KUZUSHI_DEBUG: "1" } as NodeJS.ProcessEnv,
      });
      expect(repro.kuzushiVersion).toBeTruthy();
      expect(repro.model).toBe(config.model);
      expect(repro.configHash).toMatch(/^sha256:/);
      expect(repro.scanArgs).toEqual(["scan", "./repo", "--preset", "deep"]);
      expect(repro.envFingerprint.KUZUSHI_DEBUG).toBe("1");
      expect(repro.promptOverrides).toHaveLength(1);
      expect(repro.houseRules).toEqual([]);
    });
  });

  describe("countFindingsBy", () => {
    it("buckets by severity + verdict", () => {
      const counts = countFindingsBy([
        { fingerprint: "a", verdict: "tp", displaySeverity: "high" },
        { fingerprint: "b", verdict: "tp", displaySeverity: "high" },
        { fingerprint: "c", verdict: "fp", severity: "MEDIUM" },
      ]);
      expect(counts.total).toBe(3);
      expect(counts.bySeverity.high).toBe(2);
      expect(counts.bySeverity.medium).toBe(1);
      expect(counts.byVerdict.tp).toBe(2);
      expect(counts.byVerdict.fp).toBe(1);
    });
  });

  describe("readRunSummary", () => {
    it("returns undefined when summary.json is missing", () => {
      expect(readRunSummary(dataDir)).toBeUndefined();
    });

    it("parses a v1 summary correctly", () => {
      const summary = {
        schemaVersion: RUN_SUMMARY_SCHEMA_VERSION,
        runId: "r1",
        status: "complete",
        startedAt: "2026-04-30T00:00:00Z",
        reproducibility: {
          kuzushiVersion: "0.20.0",
          model: "anthropic:claude-opus-4-7",
          configHash: "sha256:abc",
          scanArgs: [],
          envFingerprint: {},
          promptOverrides: [],
          houseRules: [],
        },
        repo: { root: "/tmp/x" },
      };
      writeFileSync(path.join(dataDir, RUN_SUMMARY_FILENAME), JSON.stringify(summary));
      const got = readRunSummary(dataDir);
      expect(got?.runId).toBe("r1");
      expect(got?.reproducibility.kuzushiVersion).toBe("0.20.0");
    });

    it("returns undefined for malformed json", () => {
      writeFileSync(path.join(dataDir, RUN_SUMMARY_FILENAME), "not-json{");
      expect(readRunSummary(dataDir)).toBeUndefined();
    });
  });
});

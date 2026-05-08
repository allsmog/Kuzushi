import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  formatEffectivePromptLine,
  formatPromptAuditTable,
  promptKeyToVerb,
  readEffectivePrompt,
  verbToPromptKey,
} from "../../src/copilot/prompt-edit.js";

describe("prompt-edit helpers", () => {
  describe("verbToPromptKey / promptKeyToVerb", () => {
    it("translates known verbs", () => {
      expect(verbToPromptKey("triage")).toBe("TRIAGE_PROMPT");
      expect(verbToPromptKey("carlini-threat-hunt")).toBe("CARLINI_THREAT_HUNT_PROMPT");
      expect(verbToPromptKey("TAINT-IRIS")).toBe("TAINT_IRIS_PROMPT");
    });

    it("returns undefined for unknown verbs", () => {
      expect(verbToPromptKey("does-not-exist")).toBeUndefined();
      expect(verbToPromptKey("")).toBeUndefined();
    });

    it("round-trips via promptKeyToVerb", () => {
      expect(promptKeyToVerb("CARLINI_THREAT_HUNT_PROMPT")).toBe("carlini-threat-hunt");
      expect(promptKeyToVerb("TRIAGE_PROMPT")).toBe("triage");
    });
  });

  describe("readEffectivePrompt", () => {
    let workDir: string;
    beforeEach(() => {
      workDir = path.join(tmpdir(), `kuzushi-prompt-edit-${Date.now()}`);
      mkdirSync(workDir, { recursive: true });
    });
    afterEach(() => {
      rmSync(workDir, { recursive: true, force: true });
    });

    it("reports 'default' when no override is set", () => {
      const out = readEffectivePrompt("triage:run", "TRIAGE_PROMPT", undefined, workDir);
      expect(out.source).toBe("default");
      expect(out.resolved).toBeUndefined();
    });

    it("reports 'inline' for plain string overrides", () => {
      const out = readEffectivePrompt(
        "triage:run",
        "TRIAGE_PROMPT",
        { TRIAGE_PROMPT: "be more careful" },
        workDir,
      );
      expect(out.source).toBe("inline");
      expect(out.resolved).toBe("be more careful");
      expect(out.byteLen).toBeGreaterThan(0);
    });

    it("reports 'file' for path-like overrides and reads the file", () => {
      const file = path.join(workDir, "triage.md");
      writeFileSync(file, "# my override\n");
      const out = readEffectivePrompt(
        "triage:run",
        "TRIAGE_PROMPT",
        { TRIAGE_PROMPT: file },
        workDir,
      );
      expect(out.source).toBe("file");
      expect(out.filePath).toBe(file);
      expect(out.resolved).toBe("# my override\n");
    });

    it("reports 'unset' when the override points at a missing file", () => {
      const out = readEffectivePrompt(
        "triage:run",
        "TRIAGE_PROMPT",
        { TRIAGE_PROMPT: "./missing.md" },
        workDir,
      );
      expect(out.source).toBe("unset");
      expect(out.filePath).toMatch(/missing\.md$/);
    });
  });

  describe("formatters", () => {
    it("formats each source shape", () => {
      expect(
        formatEffectivePromptLine({
          promptKey: "TRIAGE_PROMPT",
          toolName: "triage:run",
          source: "default",
        }),
      ).toContain("default");
      expect(
        formatEffectivePromptLine({
          promptKey: "TRIAGE_PROMPT",
          toolName: "triage:run",
          source: "inline",
          resolved: "x",
          byteLen: 1,
        }),
      ).toContain("inline");
      expect(
        formatEffectivePromptLine({
          promptKey: "TRIAGE_PROMPT",
          toolName: "triage:run",
          source: "file",
          filePath: "/tmp/x.md",
          byteLen: 42,
        }),
      ).toContain("file");
    });

    it("renders an empty audit table message", () => {
      expect(formatPromptAuditTable([])).toContain("No tools");
    });

    it("renders audit rows in a table", () => {
      const table = formatPromptAuditTable([
        {
          moduleId: "triage",
          toolName: "triage:run",
          verb: "triage",
          promptKey: "TRIAGE_PROMPT",
          effective: {
            promptKey: "TRIAGE_PROMPT",
            toolName: "triage:run",
            source: "inline",
            resolved: "x",
            byteLen: 1,
          },
        },
      ]);
      expect(table).toContain("triage:run");
      expect(table).toContain("TRIAGE_PROMPT");
      expect(table).toContain("inline");
    });
  });
});

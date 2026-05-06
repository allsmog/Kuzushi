import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Finding } from "../../src/scanners/types.js";
import { getActionableFindings, initDb, upsertFinding } from "../../src/store.js";
import type { TriageResult } from "../../src/types.js";
import { runInteractiveReview } from "../../src/ui/review.js";
import {
  runConfigConfirmation,
  runCredentialPrompt,
  runModelPrompt,
  runSetupWizard,
} from "../../src/ui/setup.js";
import { createUIStore } from "../../src/ui/state.js";

function makeFinding(fp: string): Finding {
  return {
    taskId: "semgrep",
    fingerprint: fp,
    ruleId: "test.rule",
    filePath: "src/app.ts",
    startLine: 10,
    severity: "ERROR",
    message: "test",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-79"],
    score: 54,
  };
}

function makeResult(fp: string, verdict: TriageResult["verdict"] = "tp"): TriageResult {
  return {
    fingerprint: fp,
    verdict,
    confidence: 0.92,
    rationale: "confirmed",
    verificationSteps: ["step"],
    fixPatch: null,
  };
}

describe("ui flow helpers", () => {
  const originalStdoutIsTTY = process.stdout.isTTY;

  beforeEach(() => {
    Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });
  });

  afterEach(() => {
    Object.defineProperty(process.stdout, "isTTY", {
      value: originalStdoutIsTTY,
      configurable: true,
    });
  });

  it("exposes first-run wizard state through the shared store", async () => {
    const store = createUIStore();
    const promise = runSetupWizard(store, "repo", "/tmp/repo");

    const preflight = store.getState().preflight;
    expect(store.getState().mode).toBe("preflight");
    expect(preflight?.kind).toBe("wizard");
    expect(preflight?.repoRoot).toBe("/tmp/repo");

    preflight?.onComplete({
      preset: "safe",
      model: "anthropic:claude-sonnet-4-6",
      saveLocation: "none",
    });

    await expect(promise).resolves.toEqual({
      action: "proceed",
      preset: "safe",
      model: "anthropic:claude-sonnet-4-6",
    });
    expect(store.getState().preflight).toBeNull();
    expect(store.getState().mode).toBe("running");
  });

  it("shows the returning-user confirm card inside the shared store", async () => {
    const store = createUIStore();
    const promise = runConfigConfirmation(
      store,
      {
        model: "anthropic:claude-sonnet-4-6",
        tasks: ["semgrep", "codeql"],
        preset: "deep",
        verify: true,
      },
      "repo",
      "/tmp/repo",
    );

    const preflight = store.getState().preflight;
    expect(store.getState().mode).toBe("preflight");
    expect(preflight?.kind).toBe("confirm");
    expect(preflight?.repoRoot).toBe("/tmp/repo");

    preflight?.onProceed();

    await expect(promise).resolves.toEqual({ action: "proceed" });
    expect(store.getState().preflight).toBeNull();
    expect(store.getState().mode).toBe("running");
  });

  it("returns shell-mode preflight prompts back to shell", async () => {
    const store = createUIStore();
    store.update({ mode: "shell" });

    const promise = runCredentialPrompt(store, "shell");

    const preflight = store.getState().preflight;
    expect(store.getState().mode).toBe("preflight");
    expect(preflight?.kind).toBe("credentials");

    preflight?.onCancel();

    await expect(promise).resolves.toEqual({ action: "cancel" });
    expect(store.getState().preflight).toBeNull();
    expect(store.getState().mode).toBe("shell");
  });

  it("runs the model picker as a shell-mode preflight prompt", async () => {
    const store = createUIStore();
    store.update({ mode: "shell" });

    const promise = runModelPrompt(
      store,
      {
        activeModel: "anthropic:claude-sonnet-4-6",
        availableModels: ["anthropic:claude-sonnet-4-6"],
        credentialedProviders: ["anthropic", "openai-codex"],
      },
      "shell",
    );

    const preflight = store.getState().preflight;
    expect(store.getState().mode).toBe("preflight");
    expect(preflight?.kind).toBe("model");

    preflight?.kind === "model" && preflight.onComplete("openai-codex:gpt-5.4-mini");

    await expect(promise).resolves.toEqual({
      action: "proceed",
      model: "openai-codex:gpt-5.4-mini",
    });
    expect(store.getState().preflight).toBeNull();
    expect(store.getState().mode).toBe("shell");
  });

  it("preserves the real repo root when editing from confirm back into the wizard", async () => {
    const store = createUIStore();
    const promise = runConfigConfirmation(
      store,
      {
        model: "anthropic:claude-sonnet-4-6",
        tasks: ["semgrep"],
      },
      "repo",
      "/tmp/real-root",
    );

    store.getState().preflight?.kind === "confirm" && store.getState().preflight.onEdit();
    await Promise.resolve();

    const wizard = store.getState().preflight;
    expect(wizard?.kind).toBe("wizard");
    expect(wizard?.repoRoot).toBe("/tmp/real-root");

    wizard?.kind === "wizard" &&
      wizard.onComplete({
        preset: "fast",
        model: "anthropic:claude-haiku-4-5",
        saveLocation: "none",
      });

    await expect(promise).resolves.toEqual({
      action: "proceed",
      preset: "fast",
      model: "anthropic:claude-haiku-4-5",
    });
  });

  it("runs interactive review inside the main store and updates verdicts", async () => {
    const db = initDb(":memory:");
    upsertFinding(
      db,
      makeFinding("fp-review"),
      makeResult("fp-review", "needs_review"),
      "repo",
      "HEAD",
    );

    const store = createUIStore();
    const promise = runInteractiveReview(db, "repo", store);

    const review = store.getState().review;
    expect(store.getState().mode).toBe("review");
    expect(review?.findings).toHaveLength(1);

    review?.onVerdict("fp-review", "tp");
    review?.onQuit();

    await expect(promise).resolves.toEqual({
      reviewed: 1,
      tp: 1,
      fp: 0,
      byDesign: 0,
      skipped: 0,
    });

    expect(store.getState().review).toBeNull();
    expect(store.getState().mode).toBe("summary");
    expect(getActionableFindings(db, "repo", { includeFalsePositives: true })[0]?.verdict).toBe(
      "tp",
    );
    db.close();
  });

  it("returns shell review sessions back to shell without clearing state", async () => {
    const db = initDb(":memory:");
    upsertFinding(
      db,
      makeFinding("fp-shell-review"),
      makeResult("fp-shell-review", "needs_review"),
      "repo",
      "HEAD",
    );

    const store = createUIStore();
    store.update({
      mode: "shell",
      shell: {
        modules: ["sast"],
        tools: ["sast:scan"],
        focusedModule: "sast",
        target: "/tmp/repo",
        workspace: "acme",
        history: [],
        commandHistory: [],
        moduleOptions: {},
        processing: false,
      },
    });

    const promise = runInteractiveReview(db, "repo", store, "shell");

    const review = store.getState().review;
    expect(store.getState().mode).toBe("review");
    expect(review?.findings).toHaveLength(1);

    review?.onQuit();

    await expect(promise).resolves.toEqual({
      reviewed: 0,
      tp: 0,
      fp: 0,
      byDesign: 0,
      skipped: 0,
    });
    expect(store.getState().mode).toBe("shell");
    expect(store.getState().shell?.focusedModule).toBe("sast");
    expect(store.getState().shell?.workspace).toBe("acme");
    db.close();
  });
});

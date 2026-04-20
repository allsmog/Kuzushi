import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { registerPlainTextRenderer } from "../../src/ui/plain-renderer.js";
import { createUIStore, type ShellPlan, type ShellState } from "../../src/ui/state.js";

/**
 * Capture console.log so we can assert on the plain-renderer's output.
 * The renderer uses chalk — with NO_COLOR set, chalk strips formatting
 * automatically and we compare raw text.
 */
function captureConsole(): {
  lines: string[];
  restore: () => void;
} {
  const lines: string[] = [];
  const original = console.log;
  console.log = (...args: unknown[]) => {
    lines.push(args.map((a) => (typeof a === "string" ? a : String(a))).join(" "));
  };
  return {
    lines,
    restore: () => {
      console.log = original;
    },
  };
}

function baseShell(overrides: Partial<ShellState> = {}): ShellState {
  return {
    modules: [],
    moduleCatalog: [],
    tools: [],
    focusedModule: null,
    shellView: "catalog",
    openFindingId: null,
    target: null,
    workspace: null,
    history: [],
    commandHistory: [],
    moduleOptions: {},
    processing: false,
    ...overrides,
  };
}

describe("plain-renderer Phase D.5 emitters", () => {
  const prevNoColor = process.env.NO_COLOR;
  beforeEach(() => {
    process.env.NO_COLOR = "1";
  });
  afterEach(() => {
    if (prevNoColor === undefined) delete process.env.NO_COLOR;
    else process.env.NO_COLOR = prevNoColor;
  });

  it("prints [shell] catalog on initial shell state", () => {
    const store = createUIStore();
    const cap = captureConsole();
    const unsub = registerPlainTextRenderer(store);
    store.update({ shell: baseShell({ moduleCatalog: [{} as never, {} as never] }) });
    unsub();
    cap.restore();
    expect(cap.lines.some((l) => l.includes("[shell] catalog · 2 modules"))).toBe(true);
  });

  it("prints [shell] module home on /use", () => {
    const store = createUIStore();
    const cap = captureConsole();
    const unsub = registerPlainTextRenderer(store);
    store.update({ shell: baseShell({ focusedModule: "sast", shellView: "module" }) });
    unsub();
    cap.restore();
    expect(cap.lines.some((l) => l.includes("[shell] module home (sast)"))).toBe(true);
  });

  it("prints [threats] summary with element + threat counts", () => {
    const store = createUIStore();
    const cap = captureConsole();
    const unsub = registerPlainTextRenderer(store);
    store.update({
      shell: baseShell({
        shellView: "threat-stride",
        threatModel: {
          version: "1.0",
          dfd: {
            elements: [
              { id: "P1", type: "process", name: "p", description: "", trustZone: "z" },
              { id: "E1", type: "external-entity", name: "e", description: "", trustZone: "z" },
            ],
            trustBoundaries: [],
          },
          threats: [
            {
              id: "T1",
              elementId: "P1",
              category: "spoofing",
              title: "",
              description: "",
              attackVector: "",
              preconditions: [],
              impact: "high",
              likelihood: "medium",
              existingMitigations: [],
              missingMitigations: [],
              relatedCwe: [],
              affectedFiles: [],
            },
          ],
          summary: {
            total: 1,
            bySeverity: {},
            byCategory: {
              spoofing: 1,
              tampering: 0,
              repudiation: 0,
              "information-disclosure": 0,
              "denial-of-service": 0,
              "elevation-of-privilege": 0,
            },
          },
        },
      }),
    });
    unsub();
    cap.restore();
    expect(cap.lines.some((l) => l.includes("[threats] stride · 2 elements · 1 threats"))).toBe(
      true,
    );
  });

  it("prints [since <ref>] with changed-file count", () => {
    const store = createUIStore();
    const cap = captureConsole();
    const unsub = registerPlainTextRenderer(store);
    store.update({
      shell: baseShell({
        shellView: "diff-since",
        diffSince: { ref: "main", repoRoot: "/tmp", changedFiles: ["a.ts", "b.ts"] },
      }),
    });
    unsub();
    cap.restore();
    expect(cap.lines.some((l) => l.includes("[since main] 2 changed file(s)"))).toBe(true);
  });

  it("prints [plan] summary + first-3 changes when a plan lands", () => {
    const store = createUIStore();
    const cap = captureConsole();
    const unsub = registerPlainTextRenderer(store);
    const plan: ShellPlan = {
      reasoning: "x",
      changes: [
        { option: "preset", current: "standard", proposed: "deep", why: "a" },
        { option: "maxTurnsPerHunt", current: 20, proposed: 26, why: "b" },
      ],
      unsupported: ["focus on auth"],
      roughCostDeltaUsd: 0.35,
      roughWallClockDeltaSeconds: 90,
      toolName: "sast:scan",
      producedAt: 0,
      planCostUsd: 0.0023,
      source: "console-agent/r1",
    };
    store.update({ shell: baseShell({ pendingPlan: plan }) });
    unsub();
    cap.restore();
    const joined = cap.lines.join("\n");
    expect(joined).toContain("[plan] console-agent/r1");
    expect(joined).toContain("2 changes proposed");
    expect(joined).toContain("1 unsupported");
    expect(joined).toMatch(/preset:.*standard.*→.*deep/);
    expect(joined).toMatch(/maxTurnsPerHunt:.*20.*→.*26/);
  });
});

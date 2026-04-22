/**
 * View-consistency tests — cover every migrated ShellView renders its
 * header (title + back breadcrumb) and a `ShellFooterHints`-style
 * keybind bar at a canonical 100-col terminal.
 *
 * These snapshots intentionally stay structural: we assert that the
 * rendered text contains the hint strings we expect (not pixel-perfect
 * positioning), so future tweaks to spacing or token ordering won't
 * break the suite unless an actual hint is lost.
 */

import { PassThrough, type Writable } from "node:stream";
import { render } from "ink";
import { createElement, type ReactElement } from "react";
import { describe, expect, it } from "vitest";
import { ModuleCatalog } from "../../src/ui/components/ModuleCatalog.js";
import { ModuleHome } from "../../src/ui/components/ModuleHome.js";
import { ThreatDfdView } from "../../src/ui/components/ThreatDfdView.js";
import { ThreatStrideMatrix } from "../../src/ui/components/ThreatStrideMatrix.js";
import { TuneView } from "../../src/ui/components/TuneView.js";
import type { ShellState } from "../../src/ui/state.js";

// biome-ignore lint/suspicious/noControlCharactersInRegex: strip ANSI for assertions
const ANSI_RE = /\[[0-9;]*[a-zA-Z]/g;

function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, "");
}

function renderToText(node: ReactElement, columns = 100): string {
  const stream = new PassThrough() as unknown as Writable & NodeJS.WriteStream;
  (stream as unknown as { columns: number }).columns = columns;
  (stream as unknown as { rows: number }).rows = 40;
  const chunks: Buffer[] = [];
  (stream as unknown as PassThrough).on("data", (chunk: Buffer) => chunks.push(chunk));
  const instance = render(node, { stdout: stream, debug: true });
  instance.unmount();
  (stream as unknown as PassThrough).end();
  return stripAnsi(Buffer.concat(chunks).toString("utf-8")).trimEnd();
}

function stubShell(overrides: Partial<ShellState> = {}): ShellState {
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

describe("ModuleCatalog keybind hints", () => {
  it("exposes /use /findings /tune /help /exit", () => {
    const shell = stubShell({
      workspace: "demo",
      target: "./demo",
      moduleCatalog: [
        {
          id: "sast",
          displayName: "SAST",
          category: "offense",
          description: "pipeline",
          toolCount: 1,
        },
      ],
    });
    const out = renderToText(createElement(ModuleCatalog, { shell }));
    expect(out).toContain("/use");
    expect(out).toContain("/findings");
    expect(out).toContain("/tune");
    expect(out).toContain("/help");
    expect(out).toContain("/exit");
  });
});

describe("ModuleHome keybind hints", () => {
  it("exposes t/f/b + /help after migration", () => {
    const shell = stubShell({
      focusedModule: "sast",
      shellView: "module",
      moduleCatalog: [
        {
          id: "sast",
          displayName: "SAST",
          category: "offense",
          description: "40+ task pipeline",
          toolCount: 1,
          toolSummaries: [
            { name: "sast:scan", verb: "scan", description: "run the pipeline", headless: true },
          ],
        },
      ],
    });
    const out = renderToText(createElement(ModuleHome, { shell }));
    expect(out).toContain("tune");
    expect(out).toContain("findings");
    expect(out).toContain("back");
    expect(out).toContain("/help");
    expect(out).toContain("◂ back");
  });
});

describe("TuneView keybind hints", () => {
  it("exposes s/r/x/p + /config", () => {
    const shell = stubShell({
      focusedModule: "sast",
      shellView: "tune",
      tuneSnapshot: {
        preset: "standard",
        tasks: ["semgrep"],
        verify: false,
        autoPatch: false,
        triageConcurrency: 5,
        model: "anthropic:claude-sonnet-4-5",
      },
    });
    const out = renderToText(createElement(TuneView, { shell }));
    expect(out).toContain("save");
    expect(out).toContain("reset");
    expect(out).toContain("run with these");
    expect(out).toContain("/config");
  });
});

describe("ThreatDfdView keybind hints", () => {
  it("promises 1..5 threat-view cycling plus /back (not the stale q)", () => {
    const shell = stubShell({
      shellView: "threat-dfd",
      threatModel: {
        version: "1.0",
        dfd: {
          elements: [
            {
              id: "E1",
              type: "external-entity",
              name: "user",
              description: "",
              trustZone: "internet",
            },
          ],
          trustBoundaries: [],
        },
        threats: [],
        summary: {
          total: 0,
          bySeverity: {},
          byCategory: {
            spoofing: 0,
            tampering: 0,
            repudiation: 0,
            "information-disclosure": 0,
            "denial-of-service": 0,
            "elevation-of-privilege": 0,
          },
        },
      },
    });
    const out = renderToText(createElement(ThreatDfdView, { shell }));
    expect(out).toContain("1 dfd");
    expect(out).toContain("2 stride");
    expect(out).toContain("3 stories");
    expect(out).toContain("4 scope");
    expect(out).toContain("5 summary");
    expect(out).toContain("/back");
    // The old hint claimed `q back` — but `q` is not wired in CopilotShell.
    // Ensure we no longer promise it.
    expect(out).not.toContain("q back");
  });
});

describe("ThreatStrideMatrix keybind hints", () => {
  it("promises 1..5 threat-view cycling plus /back", () => {
    const shell = stubShell({
      shellView: "threat-stride",
      threatModel: {
        version: "1.0",
        dfd: {
          elements: [
            {
              id: "E1",
              type: "external-entity",
              name: "user",
              description: "",
              trustZone: "internet",
            },
          ],
          trustBoundaries: [],
        },
        threats: [],
        summary: {
          total: 0,
          bySeverity: {},
          byCategory: {
            spoofing: 0,
            tampering: 0,
            repudiation: 0,
            "information-disclosure": 0,
            "denial-of-service": 0,
            "elevation-of-privilege": 0,
          },
        },
      },
    });
    const out = renderToText(createElement(ThreatStrideMatrix, { shell }));
    expect(out).toContain("1 dfd");
    expect(out).toContain("/back");
    expect(out).not.toContain("q back");
  });
});

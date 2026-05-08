import { afterEach, describe, expect, it } from "vitest";
import {
  clampTerminalCardWidth,
  DEFAULT_TERMINAL_COLUMNS,
  DEFAULT_TERMINAL_ROWS,
  resolveTerminalColumns,
  resolveTerminalRows,
  resolveTerminalSize,
} from "../../src/ui/terminal.js";

const OLD_ENV = { ...process.env };

afterEach(() => {
  for (const key of Object.keys(process.env)) delete process.env[key];
  Object.assign(process.env, OLD_ENV);
});

describe("terminal helpers", () => {
  it("prefer explicit source dimensions", () => {
    expect(resolveTerminalColumns({ columns: 132 })).toBe(132);
    expect(resolveTerminalRows({ rows: 41 })).toBe(41);
    expect(resolveTerminalSize({ columns: 132, rows: 41 })).toEqual({ columns: 132, rows: 41 });
  });

  it("fall back to env when no source is supplied", () => {
    process.env["COLUMNS"] = "95";
    process.env["LINES"] = "31";
    expect(resolveTerminalColumns()).toBe(95);
    expect(resolveTerminalRows()).toBe(31);
  });

  it("uses stable defaults when no source or env exists", () => {
    delete process.env["COLUMNS"];
    delete process.env["LINES"];
    expect(resolveTerminalColumns()).toBe(DEFAULT_TERMINAL_COLUMNS);
    expect(resolveTerminalRows()).toBe(DEFAULT_TERMINAL_ROWS);
  });

  it("clamps card width within min/max bounds", () => {
    expect(clampTerminalCardWidth(120, 88, 56)).toBe(88);
    expect(clampTerminalCardWidth(70, 88, 56)).toBe(66);
    expect(clampTerminalCardWidth(40, 88, 56)).toBe(36);
  });
});

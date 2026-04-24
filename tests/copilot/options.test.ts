import { describe, expect, it } from "vitest";
import {
  coerceOption,
  Datastore,
  formatOptionsTable,
  Opt,
  optionsToJsonSchema,
} from "../../src/copilot/options.js";

describe("coerceOption", () => {
  it("coerces booleans from many forms", () => {
    const spec = Opt.bool("X", { description: "b" });
    expect(coerceOption(spec, "true").value).toBe(true);
    expect(coerceOption(spec, "yes").value).toBe(true);
    expect(coerceOption(spec, "1").value).toBe(true);
    expect(coerceOption(spec, "off").value).toBe(false);
    expect(coerceOption(spec, "nope").ok).toBe(false);
  });

  it("validates port range", () => {
    const spec = Opt.port("P", { description: "p" });
    expect(coerceOption(spec, "0").ok).toBe(false);
    expect(coerceOption(spec, "80").value).toBe(80);
    expect(coerceOption(spec, "65536").ok).toBe(false);
  });

  it("enforces enum choices", () => {
    const spec = Opt.enum("MODE", { description: "m", choices: ["fast", "deep"] });
    expect(coerceOption(spec, "fast").ok).toBe(true);
    expect(coerceOption(spec, "bogus").ok).toBe(false);
  });
});

describe("Datastore", () => {
  it("resolves module → workspace → global → default", () => {
    const ds = new Datastore([Opt.string("X", { description: "", default: "def" })]);
    expect(ds.get("X")).toBe("def");
    ds.set("X", "g", "global");
    expect(ds.get("X")).toBe("g");
    ds.set("X", "w", "workspace");
    expect(ds.get("X")).toBe("w");
    ds.set("X", "m", "module");
    expect(ds.get("X")).toBe("m");
    expect(ds.whence("X")).toBe("module");
    ds.unset("X", "module");
    expect(ds.get("X")).toBe("w");
    ds.unset("X", "all");
    expect(ds.get("X")).toBe("def");
    expect(ds.whence("X")).toBe("default");
  });

  it("tracks missing required", () => {
    const ds = new Datastore([
      Opt.string("NEEDED", { description: "", required: true }),
      Opt.string("OK", { description: "", default: "ok" }),
    ]);
    expect(ds.missingRequired()).toEqual(["NEEDED"]);
    ds.set("NEEDED", "foo");
    expect(ds.missingRequired()).toEqual([]);
  });

  it("rejects invalid set values", () => {
    const ds = new Datastore([Opt.port("LPORT", { description: "" })]);
    const err = ds.set("LPORT", "abc");
    expect(err).toMatch(/port/);
    expect(ds.get("LPORT")).toBeUndefined();
  });

  it("accepts opaque values for unknown names", () => {
    const ds = new Datastore();
    expect(ds.set("UNKNOWN", "whatever")).toBeNull();
    expect(ds.get("UNKNOWN")).toBe("whatever");
  });
});

describe("optionsToJsonSchema", () => {
  it("produces a valid JSON schema with required + enum", () => {
    const schema = optionsToJsonSchema([
      Opt.string("TARGET", { description: "t", required: true }),
      Opt.enum("MODE", { description: "m", choices: ["fast", "deep"], default: "fast" }),
      Opt.port("LPORT", { description: "p", default: 4444 }),
    ]);
    expect(schema).toMatchObject({
      type: "object",
      required: ["TARGET"],
      properties: {
        TARGET: { type: "string" },
        MODE: { type: "string", enum: ["fast", "deep"], default: "fast" },
        LPORT: { type: "integer", minimum: 1, maximum: 65535, default: 4444 },
      },
    });
  });
});

describe("formatOptionsTable", () => {
  it("renders a table with required flag and missing marker", () => {
    const ds = new Datastore([
      Opt.string("RHOST", { description: "Host", required: true }),
      Opt.port("RPORT", { description: "Port", required: true, default: 80 }),
    ]);
    const out = formatOptionsTable(ds, { highlightMissing: true });
    expect(out).toContain("RHOST *");
    expect(out).toContain("Host");
    expect(out).toContain("RPORT");
    expect(out).toContain("80");
  });

  it("partitions advanced options", () => {
    const ds = new Datastore([
      Opt.string("X", { description: "normal" }),
      Opt.string("Y", { description: "adv", advanced: true }),
    ]);
    expect(formatOptionsTable(ds)).toContain("X");
    expect(formatOptionsTable(ds)).not.toContain("Y  ");
    expect(formatOptionsTable(ds, { advanced: true })).toContain("Y");
  });

  it("wraps long descriptions under the Description column", () => {
    const ds = new Datastore([
      Opt.string("discovery", {
        description: "auto = detect monorepo, flat = single project, modules = force per-module.",
        default: "auto",
      }),
    ]);
    // 80-col terminal is typical; descStart = 2 + 9 + 2 + 15 + 2 + 8 + 2 = 40.
    // descWidth = 80 - 40 - 1 = 39 → description should wrap to >=2 lines
    // with continuation padded to 40 columns.
    const out = formatOptionsTable(ds, { availableWidth: 80 });
    const lines = out.split("\n");
    // First body line carries the option name, value, required, and start of description.
    const leader = lines.find((l) => l.includes("discovery"));
    expect(leader).toBeDefined();
    expect(leader!).toMatch(/discovery\s+auto\s+no\s+auto = detect monorepo/);
    // Continuation line should start with exactly 40 spaces then more description text.
    const cont = lines.find(
      (l) => l.startsWith(" ".repeat(40)) && !l.includes("discovery") && l.trim().length > 0,
    );
    expect(cont).toBeDefined();
    expect(cont!.length).toBeLessThanOrEqual(80);
    // No line should exceed the target width.
    for (const line of lines) {
      expect(line.length).toBeLessThanOrEqual(80);
    }
  });

  it("does not break mid-word when width is wide enough", () => {
    const ds = new Datastore([
      Opt.string("threatModel", {
        description: "Run PASTA S1-S4 threat modeling.",
        default: "true",
      }),
    ]);
    const out = formatOptionsTable(ds, { availableWidth: 120 });
    expect(out).toContain("Run PASTA S1-S4 threat modeling.");
    expect(out.split("\n").filter((l) => l.trim().length > 0)).toHaveLength(3); // header + sep + one body line
  });
});

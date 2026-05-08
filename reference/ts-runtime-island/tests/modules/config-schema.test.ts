import { describe, expect, it } from "vitest";
import { validateConfigAgainstSchema } from "../../src/modules/registry.js";

describe("validateConfigAgainstSchema", () => {
  it("accepts a matching object config", () => {
    expect(
      validateConfigAgainstSchema(
        { apiKey: "x", retries: 3 },
        {
          type: "object",
          properties: {
            apiKey: { type: "string" },
            retries: { type: "integer" },
          },
          required: ["apiKey"],
        },
      ),
    ).toBeNull();
  });

  it("rejects when required field missing", () => {
    const err = validateConfigAgainstSchema({}, { type: "object", required: ["apiKey"] });
    expect(err).toMatch(/missing required config field "apiKey"/);
  });

  it("rejects on type mismatch", () => {
    const err = validateConfigAgainstSchema(
      { apiKey: 42 },
      { type: "object", properties: { apiKey: { type: "string" } } },
    );
    expect(err).toMatch(/expected type string/);
  });

  it("accepts integer-valued number against number type", () => {
    expect(
      validateConfigAgainstSchema(
        { pct: 10 },
        { type: "object", properties: { pct: { type: "number" } } },
      ),
    ).toBeNull();
  });

  it("rejects when value not in enum", () => {
    const err = validateConfigAgainstSchema(
      { mode: "invalid" },
      { type: "object", properties: { mode: { enum: ["fast", "slow"] } } },
    );
    expect(err).toMatch(/must be one of/);
  });

  it("rejects non-object config", () => {
    expect(validateConfigAgainstSchema(null, {})).toMatch(/must be a plain object/);
    expect(validateConfigAgainstSchema([], {})).toMatch(/must be a plain object/);
    expect(validateConfigAgainstSchema("x", {})).toMatch(/must be a plain object/);
  });

  it("rejects unsupported top-level type", () => {
    const err = validateConfigAgainstSchema({}, { type: "array" });
    expect(err).toMatch(/unsupported/);
  });
});

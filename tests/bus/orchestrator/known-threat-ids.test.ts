import { describe, expect, it } from "vitest";
import { collectKnownThreatIds } from "../../../src/bus/orchestrator/triage-dispatcher.js";

describe("collectKnownThreatIds", () => {
  it("extracts id strings from threat-model-randori output", () => {
    const outputs = new Map<string, unknown>([
      [
        "threat-model-randori",
        {
          threats: [
            { id: "T-01", title: "a" },
            { id: "T-02", title: "b" },
            { id: "T-03", title: "c" },
          ],
        },
      ],
    ]);
    expect(collectKnownThreatIds(outputs)).toEqual(["T-01", "T-02", "T-03"]);
  });

  it("returns empty when no threat-model-randori output is present", () => {
    expect(collectKnownThreatIds(new Map())).toEqual([]);
  });

  it("skips threats without an id", () => {
    const outputs = new Map<string, unknown>([
      [
        "threat-model-randori",
        {
          threats: [{ id: "T-01" }, {}, { id: "" }, { id: "T-02" }],
        },
      ],
    ]);
    expect(collectKnownThreatIds(outputs)).toEqual(["T-01", "T-02"]);
  });

  it("returns empty when threats is not an array", () => {
    const outputs = new Map<string, unknown>([["threat-model-randori", { threats: "nope" }]]);
    expect(collectKnownThreatIds(outputs)).toEqual([]);
  });
});

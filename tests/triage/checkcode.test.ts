import { describe, expect, it } from "vitest";
import {
  CHECK_RANK,
  Check,
  checkCodeToVerdict,
  formatCheckCode,
  maxCheckCode,
} from "../../src/triage/checkcode.js";

describe("CheckCode factories", () => {
  it("constructs each kind with optional details", () => {
    expect(Check.unknown("why")).toEqual({ kind: "unknown", reason: "why" });
    expect(Check.safe()).toEqual({ kind: "safe" });
    expect(Check.detected("banner match")).toMatchObject({
      kind: "detected",
      reason: "banner match",
    });
    expect(Check.appears("reachable")).toMatchObject({ kind: "appears" });
    expect(Check.vulnerable("RCE", { body: "..." }, { cve: "2024-1" })).toMatchObject({
      kind: "vulnerable",
      reason: "RCE",
      details: { body: "..." },
      vuln: { cve: "2024-1" },
    });
    expect(Check.unsupported("no check method")).toEqual({
      kind: "unsupported",
      reason: "no check method",
    });
  });
});

describe("CHECK_RANK", () => {
  it("orders weakest to strongest evidence", () => {
    expect(CHECK_RANK.unsupported).toBeLessThan(CHECK_RANK.unknown);
    expect(CHECK_RANK.unknown).toBeLessThan(CHECK_RANK.safe);
    expect(CHECK_RANK.safe).toBeLessThan(CHECK_RANK.detected);
    expect(CHECK_RANK.detected).toBeLessThan(CHECK_RANK.appears);
    expect(CHECK_RANK.appears).toBeLessThan(CHECK_RANK.vulnerable);
  });
});

describe("checkCodeToVerdict", () => {
  it("maps onto Kuzushi's existing Verdict enum", () => {
    expect(checkCodeToVerdict(Check.vulnerable())).toBe("tp");
    expect(checkCodeToVerdict(Check.safe())).toBe("fp");
    expect(checkCodeToVerdict(Check.appears())).toBe("needs_review");
    expect(checkCodeToVerdict(Check.detected())).toBe("needs_review");
    expect(checkCodeToVerdict(Check.unknown())).toBe("needs_review");
    expect(checkCodeToVerdict(Check.unsupported())).toBe("needs_review");
  });
});

describe("maxCheckCode", () => {
  it("picks the strongest evidence in a list", () => {
    expect(maxCheckCode([Check.safe(), Check.detected(), Check.appears()])?.kind).toBe("appears");
    expect(maxCheckCode([Check.unknown(), Check.vulnerable()])?.kind).toBe("vulnerable");
    expect(maxCheckCode([])).toBeUndefined();
  });
});

describe("formatCheckCode", () => {
  it("renders kind + optional reason", () => {
    expect(formatCheckCode(Check.vulnerable("RCE via deserialization"))).toBe(
      "VULNERABLE: RCE via deserialization",
    );
    expect(formatCheckCode(Check.safe())).toBe("SAFE");
  });
});

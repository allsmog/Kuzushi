import { describe, expect, it } from "vitest";
import {
  classifyVerdict,
  parseCryptoBehavioralResult,
  parseTimingResult,
  parseWycheproofResult,
} from "../../src/crypto-behavioral/result-parser.js";

describe("crypto behavioral result parser", () => {
  it("parses timing results and classifies vulnerable executions", () => {
    const stdout = [
      "noise",
      'CRYPTO_RESULT:{"fingerprint":"fp-1","testType":"timing","verdict":"vulnerable","summary":"timing leak observed","timing":{"constantTime":false,"tStatistic":5.12,"pValue":0.0001,"meanANs":101.2,"meanBNs":84.7,"iterations":10000}}',
    ].join("\n");

    const parsed = parseCryptoBehavioralResult(stdout);
    expect(parseTimingResult(stdout)).toEqual({
      constantTime: false,
      tStatistic: 5.12,
      pValue: 0.0001,
      meanANs: 101.2,
      meanBNs: 84.7,
      iterations: 10000,
    });
    expect(classifyVerdict("timing", parsed, { exitCode: 0, verdict: "PASS" })).toBe("vulnerable");
  });

  it("parses edge-case results and classifies secure executions", () => {
    const stdout = [
      'CRYPTO_RESULT:{"fingerprint":"fp-2","testType":"edge-case","verdict":"secure","summary":"hostname mismatch rejected","confirmed":false,"observedBehavior":"connection rejected","expectedBehavior":"reject invalid certificate"}',
    ].join("\n");

    expect(parseWycheproofResult(stdout)).toEqual({
      confirmed: false,
      observedBehavior: "connection rejected",
      expectedBehavior: "reject invalid certificate",
    });
    expect(
      classifyVerdict("edge-case", parseCryptoBehavioralResult(stdout), {
        exitCode: 1,
        verdict: "FAIL",
      }),
    ).toBe("secure");
  });

  it("classifies inconclusive and timeout/error executions", () => {
    const stdout =
      'CRYPTO_RESULT:{"fingerprint":"fp-3","testType":"weak-prng","verdict":"inconclusive","summary":"insufficient entropy sample"}';

    const parsed = parseCryptoBehavioralResult(stdout);
    expect(classifyVerdict("weak-prng", parsed, { exitCode: 2, verdict: "FAIL" })).toBe(
      "inconclusive",
    );
    expect(classifyVerdict("weak-prng", parsed, { verdict: "TIMEOUT" })).toBe("error");
  });

  it("throws on malformed output", () => {
    expect(() => parseCryptoBehavioralResult("stdout without marker")).toThrow(
      "CRYPTO_RESULT line not found in stdout.",
    );
  });
});

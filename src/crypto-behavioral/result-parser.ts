import { isRecord, toErrorMessage } from "../utils.js";
import type {
  CryptoBehavioralExecutionVerdict,
  CryptoBehavioralScriptOutput,
  CryptoBehavioralTestType,
  CryptoBehavioralVerdict,
  TimingAnalysisResult,
  WycheproofResult,
} from "./types.js";

export interface CryptoBehavioralExecutionSummary {
  exitCode?: number | null;
  verdict?: CryptoBehavioralExecutionVerdict;
}

export interface ParsedCryptoBehavioralResult {
  result: CryptoBehavioralScriptOutput;
  timing?: TimingAnalysisResult;
  wycheproof?: WycheproofResult;
}

export function parseCryptoBehavioralResult(stdout: string): ParsedCryptoBehavioralResult {
  const result = parseCryptoResult(stdout);
  const timing = parseTimingFromResult(result);
  const wycheproof = parseWycheproofFromResult(result);

  return {
    result,
    timing: timing ?? undefined,
    wycheproof: wycheproof ?? undefined,
  };
}

export function parseTimingResult(stdout: string): TimingAnalysisResult {
  const parsed = parseTimingFromResult(parseCryptoResult(stdout));
  if (!parsed) {
    throw new Error("CRYPTO_RESULT does not contain timing analysis fields.");
  }
  return parsed;
}

export function parseWycheproofResult(stdout: string): WycheproofResult {
  const parsed = parseWycheproofFromResult(parseCryptoResult(stdout));
  if (!parsed) {
    throw new Error("CRYPTO_RESULT does not contain edge-case behavioral fields.");
  }
  return parsed;
}

export function classifyVerdict(
  testType: CryptoBehavioralTestType,
  parsed: ParsedCryptoBehavioralResult | undefined,
  execution: CryptoBehavioralExecutionSummary | undefined,
): CryptoBehavioralVerdict {
  if (execution?.verdict === "TIMEOUT" || execution?.verdict === "ERROR") {
    return "error";
  }

  switch (execution?.exitCode) {
    case 0:
      return "vulnerable";
    case 1:
      return "secure";
    case 2:
      return "inconclusive";
    case 3:
      return "error";
    default:
      break;
  }

  const rawVerdict = parsed?.result?.verdict;
  if (rawVerdict === "vulnerable" || rawVerdict === "secure" || rawVerdict === "inconclusive" || rawVerdict === "error") {
    return rawVerdict;
  }

  if (testType === "timing" && parsed?.timing) {
    return parsed.timing.constantTime ? "secure" : "vulnerable";
  }

  if ((testType === "ecb-mode" || testType === "edge-case") && parsed?.wycheproof) {
    return parsed.wycheproof.confirmed ? "vulnerable" : "secure";
  }

  return "inconclusive";
}

function parseCryptoResult(stdout: string): CryptoBehavioralScriptOutput {
  const marker = "CRYPTO_RESULT:";
  const line = stdout
    .split(/\r?\n/)
    .map((entry) => entry.trim())
    .reverse()
    .find((entry) => entry.startsWith(marker));

  if (!line) {
    throw new Error("CRYPTO_RESULT line not found in stdout.");
  }

  const rawJson = line.slice(marker.length).trim();
  try {
    const parsed = JSON.parse(rawJson);
    if (!isRecord(parsed)) {
      throw new Error("CRYPTO_RESULT payload is not an object.");
    }

    const verdict = asVerdict(parsed["verdict"]);
    return {
      fingerprint: asString(parsed["fingerprint"]),
      testType: asTestType(parsed["testType"] ?? parsed["test_type"]),
      verdict,
      summary: asString(parsed["summary"]),
      timing: isRecord(parsed["timing"]) ? normalizeTiming(parsed["timing"]) ?? undefined : undefined,
      observedBehavior: asOptionalString(parsed["observedBehavior"] ?? parsed["observed_behavior"]),
      expectedBehavior: asOptionalString(parsed["expectedBehavior"] ?? parsed["expected_behavior"]),
      algorithmConfirmed: asOptionalString(parsed["algorithmConfirmed"] ?? parsed["algorithm_confirmed"]),
      keyLengthBits: asOptionalNumber(parsed["keyLengthBits"] ?? parsed["key_length_bits"]),
      confirmed: asOptionalBoolean(parsed["confirmed"]),
    };
  } catch (error) {
    throw new Error(`Invalid CRYPTO_RESULT payload: ${toErrorMessage(error)}`);
  }
}

function parseTimingFromResult(
  result: CryptoBehavioralScriptOutput,
): TimingAnalysisResult | null {
  if (result.timing && typeof result.timing.constantTime === "boolean") {
    return {
      constantTime: result.timing.constantTime,
      tStatistic: asNullableNumber(result.timing.tStatistic),
      pValue: asNullableNumber(result.timing.pValue),
      meanANs: asNullableNumber(result.timing.meanANs),
      meanBNs: asNullableNumber(result.timing.meanBNs),
      iterations: asNullableNumber(result.timing.iterations),
    };
  }

  return null;
}

function parseWycheproofFromResult(
  result: CryptoBehavioralScriptOutput,
): WycheproofResult | null {
  if (!result.observedBehavior && !result.expectedBehavior && typeof result.confirmed !== "boolean") {
    return null;
  }

  return {
    confirmed: result.confirmed === true,
    observedBehavior: result.observedBehavior ?? "",
    expectedBehavior: result.expectedBehavior ?? "",
  };
}

function normalizeTiming(
  value: Record<string, unknown>,
): Partial<TimingAnalysisResult> | null {
  const constantTime = asOptionalBoolean(value["constantTime"] ?? value["constant_time"]);
  if (typeof constantTime !== "boolean") {
    return null;
  }

  return {
    constantTime,
    tStatistic: asNullableNumber(value["tStatistic"] ?? value["t_statistic"]),
    pValue: asNullableNumber(value["pValue"] ?? value["p_value"]),
    meanANs: asNullableNumber(value["meanANs"] ?? value["mean_a_ns"]),
    meanBNs: asNullableNumber(value["meanBNs"] ?? value["mean_b_ns"]),
    iterations: asNullableNumber(value["iterations"]),
  };
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function asOptionalString(value: unknown): string | undefined {
  const normalized = asString(value);
  return normalized || undefined;
}

function asOptionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function asNullableNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asOptionalBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function asVerdict(value: unknown): CryptoBehavioralVerdict {
  return value === "vulnerable" || value === "secure" || value === "inconclusive" || value === "error"
    ? value
    : "inconclusive";
}

function asTestType(value: unknown): CryptoBehavioralTestType {
  switch (value) {
    case "timing":
    case "ecb-mode":
    case "weak-hash":
    case "weak-prng":
    case "key-length":
    case "edge-case":
      return value;
    default:
      return "edge-case";
  }
}

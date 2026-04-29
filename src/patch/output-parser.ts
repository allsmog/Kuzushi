export interface PatchSynthesisOutput {
  diff: string;
  explanation: string;
}

export function parsePatchSynthesisOutput(raw: unknown): PatchSynthesisOutput {
  if (isPatchSynthesisRecord(raw)) {
    return parsePatchSynthesisRecord(raw);
  }
  if (typeof raw === "string") {
    return parsePatchSynthesisText(raw);
  }
  throw new Error("Unexpected patch synthesis output format.");
}

function isPatchSynthesisRecord(value: unknown): value is Record<string, unknown> {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function parsePatchSynthesisRecord(record: Record<string, unknown>): PatchSynthesisOutput {
  const diff = typeof record["diff"] === "string" ? record["diff"] : "";
  const explanation = typeof record["explanation"] === "string" ? record["explanation"] : "";
  if (diff.trim().length === 0) {
    throw new Error("Empty diff in patch synthesis output.");
  }
  return { diff, explanation };
}

function parsePatchSynthesisText(text: string): PatchSynthesisOutput {
  const jsonText = extractJsonObjectText(text);
  if (!jsonText) {
    throw new Error("Could not extract JSON from patch synthesis response.");
  }
  return parsePatchSynthesisOutput(JSON.parse(jsonText));
}

function extractJsonObjectText(text: string): string | undefined {
  const braceStart = text.indexOf("{");
  const braceEnd = text.lastIndexOf("}");
  if (braceStart < 0 || braceEnd <= braceStart) return undefined;
  return text.slice(braceStart, braceEnd + 1);
}

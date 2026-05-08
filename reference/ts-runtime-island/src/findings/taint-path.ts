import type { TaintPathStep } from "../scanners/types.js";

function sanitizeSnippet(snippet: string): string {
  return snippet.replace(/\s+/g, " ").trim().slice(0, 240);
}

export function formatTaintPathForPrompt(
  taintPath: TaintPathStep[] | undefined,
  maxSteps = 20,
): string {
  if (!taintPath || taintPath.length === 0) {
    return "Structured taint path: none";
  }

  const lines = ["## Full Taint Flow Path"];
  for (const [index, step] of taintPath.slice(0, maxSteps).entries()) {
    lines.push(
      `Step ${index + 1}: ${step.filePath}:${step.line}${step.message ? ` - ${step.message}` : ""}`,
    );
    if (step.snippet) {
      lines.push(`  Code: ${sanitizeSnippet(step.snippet)}`);
    }
  }

  if (taintPath.length > maxSteps) {
    lines.push(`... ${taintPath.length - maxSteps} more step(s) omitted for brevity`);
  }

  return lines.join("\n");
}

export function summarizeTaintPath(
  taintPath: TaintPathStep[] | undefined,
  maxSteps = 4,
): string | undefined {
  if (!taintPath || taintPath.length === 0) {
    return undefined;
  }

  const summary = taintPath
    .slice(0, maxSteps)
    .map((step) => `${step.filePath}:${step.line}`)
    .join(" -> ");

  if (taintPath.length > maxSteps) {
    return `${summary} -> +${taintPath.length - maxSteps} more`;
  }

  return summary;
}

export function formatTaintPathForDisplay(
  taintPath: TaintPathStep[] | undefined,
  maxSteps = 6,
): string[] {
  if (!taintPath || taintPath.length === 0) {
    return [];
  }

  const lines = taintPath.slice(0, maxSteps).map((step, index) => {
    const message = step.message ? ` - ${step.message}` : "";
    const snippet = step.snippet ? ` (${sanitizeSnippet(step.snippet)})` : "";
    return `${index + 1}. ${step.filePath}:${step.line}${message}${snippet}`;
  });

  if (taintPath.length > maxSteps) {
    lines.push(`... ${taintPath.length - maxSteps} more step(s) omitted`);
  }

  return lines;
}

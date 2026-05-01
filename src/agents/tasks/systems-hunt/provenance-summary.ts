import { readFile } from "node:fs/promises";
import path from "node:path";
import type {
  SystemsAliasBehavior,
  SystemsCodeLocation,
  SystemsProvenanceFact,
  SystemsProvenanceFactKind,
  SystemsProvenanceState,
  SystemsProvenanceSummary,
} from "./types.js";

interface FunctionRange {
  functionName: string;
  filePath: string;
  startLine: number;
  endLine: number;
}

const SUMMARY_SCORE_BY_KIND: Record<SystemsProvenanceFactKind, number> = {
  "shared-origin": 2,
  "alias-preserving-transport": 4,
  "iterator-propagation": 2,
  "scatterlist-alias": 4,
  "request-alias": 5,
  "write-through-shared": 6,
  "validation-before-trust": 2,
  "failure-after-mutation": 6,
  "private-copy-guard": 5,
  "nonalias-guard": 5,
  "rollback-guard": 5,
};

export async function buildProvenanceSummaries(args: {
  repoRoot: string;
  filePaths: string[];
  facts: SystemsProvenanceFact[];
  limit: number;
}): Promise<SystemsProvenanceSummary[]> {
  const { repoRoot, filePaths, facts, limit } = args;
  if (facts.length === 0 || limit <= 0) return [];

  const rangesByFile = new Map<string, FunctionRange[]>();
  await Promise.all(
    filePaths.map(async (filePath) => {
      rangesByFile.set(filePath, await inferFunctionRanges(repoRoot, filePath));
    }),
  );

  const grouped = new Map<string, { range: FunctionRange; facts: SystemsProvenanceFact[] }>();
  for (const fact of facts) {
    const range = findContainingFunction(rangesByFile.get(fact.filePath) ?? [], fact) ?? {
      functionName: "<file-scope>",
      filePath: fact.filePath,
      startLine: fact.line,
      endLine: fact.line,
    };
    const key = `${range.filePath}:${range.functionName}:${range.startLine}`;
    const bucket = grouped.get(key) ?? { range, facts: [] };
    bucket.facts.push(fact);
    grouped.set(key, bucket);
  }

  const summaries = [...grouped.values()]
    .map(({ range, facts: functionFacts }) => summarizeFunction(range, functionFacts))
    .sort((left, right) => {
      if (right.score !== left.score) return right.score - left.score;
      if (left.filePath !== right.filePath) return left.filePath.localeCompare(right.filePath);
      return left.startLine - right.startLine;
    });
  const functionSummaries = summaries.filter((summary) => summary.functionName !== "<file-scope>");
  return (functionSummaries.length > 0 ? functionSummaries : summaries).slice(0, limit);
}

async function inferFunctionRanges(repoRoot: string, filePath: string): Promise<FunctionRange[]> {
  const lines = await readLines(repoRoot, filePath);
  if (!lines) return [];

  const ranges: FunctionRange[] = [];
  let pending:
    | {
        functionName: string;
        startLine: number;
        header: string;
      }
    | undefined;

  for (let index = 0; index < lines.length; index += 1) {
    const line = stripLineComment(lines[index] ?? "");
    if (!line.trim()) continue;

    if (!pending) {
      const oneLineName = parseFunctionName(line);
      if (!oneLineName) continue;
      pending = { functionName: oneLineName, startLine: index + 1, header: line };
    } else {
      pending.header = `${pending.header} ${line.trim()}`;
    }

    if (!pending.header.includes("{")) {
      if (pending.header.includes(";")) pending = undefined;
      continue;
    }

    const endLine = findFunctionEnd(lines, index);
    if (endLine >= pending.startLine) {
      ranges.push({
        functionName: pending.functionName,
        filePath,
        startLine: pending.startLine,
        endLine,
      });
      index = Math.max(index, endLine - 1);
    }
    pending = undefined;
  }

  return ranges;
}

function parseFunctionName(line: string): string | undefined {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) return undefined;
  if (/^(if|for|while|switch|return|sizeof)\b/.test(trimmed)) return undefined;
  if (/[=,]\s*$/.test(trimmed)) return undefined;
  if (/^\s*(?:typedef|struct|union|enum)\b/.test(trimmed)) return undefined;

  const match =
    trimmed.match(
      /^(?:static\s+)?(?:inline\s+)?(?:__always_inline\s+)?(?:[\w:*&[\]]+\s+)+([A-Za-z_]\w*)\s*\([^;]*\)?\s*(?:\{|$)/,
    ) ?? trimmed.match(/^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*[<(]/);
  const name = match?.[1]?.trim();
  if (!name || ["if", "for", "while", "switch", "return"].includes(name)) return undefined;
  return name;
}

function findFunctionEnd(lines: string[], bodyStartIndex: number): number {
  let depth = 0;
  let sawOpen = false;
  for (let index = bodyStartIndex; index < lines.length; index += 1) {
    const line = stripLineComment(lines[index] ?? "");
    for (const char of line) {
      if (char === "{") {
        depth += 1;
        sawOpen = true;
      } else if (char === "}") {
        depth -= 1;
        if (sawOpen && depth <= 0) return index + 1;
      }
    }
  }
  return lines.length;
}

function findContainingFunction(
  ranges: FunctionRange[],
  fact: SystemsProvenanceFact,
): FunctionRange | undefined {
  return ranges.find((range) => fact.line >= range.startLine && fact.line <= range.endLine);
}

function summarizeFunction(
  range: FunctionRange,
  facts: SystemsProvenanceFact[],
): SystemsProvenanceSummary {
  const orderedFacts = [...facts].sort((left, right) => left.line - right.line);
  const states = unique(orderedFacts.map((fact) => fact.state));
  const factKinds = unique(orderedFacts.map((fact) => fact.kind));
  const resourceFamilies = unique(orderedFacts.map((fact) => fact.resourceFamily));
  const hardGuards = orderedFacts
    .filter((fact) => fact.strength === "hard-guard")
    .map((fact) => `${fact.kind}@${fact.line}: ${fact.snippet}`)
    .slice(0, 4);
  const writesThroughSharedAlias = factKinds.includes("write-through-shared");
  const validationFailureAfterMutation = hasFailureAfterMutation(orderedFacts);
  const aliasBehavior = inferAliasBehavior(factKinds, hardGuards.length > 0);
  const evidence = orderedFacts.slice(0, 8).map(
    (fact): SystemsCodeLocation => ({
      filePath: fact.filePath,
      line: fact.line,
      snippet: fact.snippet,
      reason: `${fact.state}/${fact.kind}/${fact.strength}`,
    }),
  );
  const score = scoreFacts(orderedFacts, validationFailureAfterMutation, hardGuards.length > 0);

  return {
    functionName: range.functionName,
    filePath: range.filePath,
    startLine: range.startLine,
    endLine: range.endLine,
    states,
    factKinds,
    resourceFamilies,
    aliasBehavior,
    writesThroughSharedAlias,
    validationFailureAfterMutation,
    hardGuards,
    evidence,
    summary: buildSummaryText({
      functionName: range.functionName,
      states,
      factKinds,
      resourceFamilies,
      aliasBehavior,
      writesThroughSharedAlias,
      validationFailureAfterMutation,
      hardGuardCount: hardGuards.length,
    }),
    score,
  };
}

function hasFailureAfterMutation(facts: SystemsProvenanceFact[]): boolean {
  const firstWrite = facts.find((fact) => fact.kind === "write-through-shared");
  if (!firstWrite) return false;
  return facts.some(
    (fact) =>
      (fact.kind === "failure-after-mutation" || fact.state === "FAILED_AFTER_MUTATION") &&
      fact.line >= firstWrite.line,
  );
}

function inferAliasBehavior(
  factKinds: SystemsProvenanceFactKind[],
  hasHardGuard: boolean,
): SystemsAliasBehavior {
  if (hasHardGuard) return "breaks-alias";
  if (factKinds.includes("request-alias")) return "creates-alias";
  if (
    factKinds.includes("alias-preserving-transport") ||
    factKinds.includes("iterator-propagation") ||
    factKinds.includes("scatterlist-alias")
  ) {
    return "preserves-alias";
  }
  if (factKinds.includes("shared-origin")) return "requires-unknown-alias";
  return "none";
}

function scoreFacts(
  facts: SystemsProvenanceFact[],
  validationFailureAfterMutation: boolean,
  hasHardGuard: boolean,
): number {
  const base = facts.reduce((sum, fact) => sum + SUMMARY_SCORE_BY_KIND[fact.kind], 0);
  return base + (validationFailureAfterMutation ? 8 : 0) - (hasHardGuard ? 6 : 0);
}

function buildSummaryText(args: {
  functionName: string;
  states: SystemsProvenanceState[];
  factKinds: SystemsProvenanceFactKind[];
  resourceFamilies: string[];
  aliasBehavior: SystemsAliasBehavior;
  writesThroughSharedAlias: boolean;
  validationFailureAfterMutation: boolean;
  hardGuardCount: number;
}): string {
  const effects = [
    `alias=${args.aliasBehavior}`,
    args.writesThroughSharedAlias ? "writes-through-shared" : "",
    args.validationFailureAfterMutation ? "failure-after-mutation" : "",
    args.hardGuardCount > 0 ? `hard-guards=${args.hardGuardCount}` : "",
  ].filter(Boolean);

  return [
    `${args.functionName}: ${effects.join(", ") || "provenance signal"}`,
    `states=${args.states.join("/") || "none"}`,
    `families=${args.resourceFamilies.join("/") || "unknown"}`,
    `facts=${args.factKinds.join("/") || "none"}`,
  ].join(" | ");
}

async function readLines(repoRoot: string, filePath: string): Promise<string[] | undefined> {
  try {
    const content = await readFile(path.join(repoRoot, filePath), "utf-8");
    return content.split(/\r?\n/u);
  } catch {
    return undefined;
  }
}

function stripLineComment(line: string): string {
  return line.replace(/\/\/.*$/u, "");
}

function unique<T extends string>(values: T[]): T[] {
  return [...new Set(values.filter(Boolean))];
}

export const __systemsProvenanceSummaryInternals = {
  buildProvenanceSummaries,
  inferFunctionRanges,
};

import { createSimpleTextIndexProvider } from "../../../analysis-support/index.js";

export type GroundingStatus = "verified" | "weak" | "invalid";

export interface GroundingEvidence {
  filePath: string;
  line: number;
  snippet: string;
}

export interface GroundingAssessment {
  status: GroundingStatus;
  reasons: string[];
  matchCount: number;
  evidence: GroundingEvidence[];
}

export interface CallableGroundingTarget {
  callable: string;
  receiverHint?: string | null;
  argIndex?: number | null;
}

export interface GroundedCallable<T extends CallableGroundingTarget> {
  item: T;
  grounding: GroundingAssessment;
}

export interface GroundedNamedHint {
  name: string;
  grounding: GroundingAssessment;
}

export async function groundCallableTargets<T extends CallableGroundingTarget>(
  repoRoot: string,
  items: T[],
): Promise<Array<GroundedCallable<T>>> {
  if (items.length === 0) {
    return [];
  }

  const index = await createSimpleTextIndexProvider(repoRoot);
  const grounded: Array<GroundedCallable<T>> = [];
  for (const item of items) {
    const argIndex = typeof item.argIndex === "number" ? item.argIndex : null;
    const matches = await index.findSymbol({
      symbol: item.callable,
      receiverHint: item.receiverHint ?? null,
      maxResults: 6,
    });

    const strongMatches = matches.filter((match) => match.confidence >= 0.75);
    const receiverMatched = !item.receiverHint || matches.some((match) => match.receiverMatched);
    const argIndexPlausible = argIndex == null
      ? true
      : matches.some((match) => match.arityHint == null || match.arityHint > argIndex);

    let status: GroundingStatus;
    const reasons: string[] = [];
    if (matches.length === 0) {
      status = "invalid";
      reasons.push("callable_not_found_in_repo");
    } else if (!argIndexPlausible) {
      status = receiverMatched ? "weak" : "invalid";
      reasons.push("arg_index_not_observed");
    } else if (receiverMatched && strongMatches.length > 0) {
      status = "verified";
      reasons.push("callable_matched_with_receiver_context");
    } else {
      status = "weak";
      reasons.push(receiverMatched ? "callable_matched_without_strong_callsite" : "callable_matched_without_receiver_context");
    }

    grounded.push({
      item,
      grounding: {
        status,
        reasons,
        matchCount: matches.length,
        evidence: matches.slice(0, 3).map((match) => ({
          filePath: match.filePath,
          line: match.line,
          snippet: match.snippet,
        })),
      },
    });
  }

  return grounded;
}

export async function groundNamedHints(
  repoRoot: string,
  names: string[],
): Promise<GroundedNamedHint[]> {
  if (names.length === 0) {
    return [];
  }

  const index = await createSimpleTextIndexProvider(repoRoot);
  const grounded: GroundedNamedHint[] = [];
  for (const name of names) {
    const matches = await index.searchText(name, { maxResults: 4 });
    grounded.push({
      name,
      grounding: {
        status: matches.length > 0 ? "verified" : "invalid",
        reasons: matches.length > 0 ? ["hint_observed_in_repo"] : ["hint_not_observed_in_repo"],
        matchCount: matches.length,
        evidence: matches.slice(0, 3).map((match) => ({
          filePath: match.filePath,
          line: match.line,
          snippet: match.snippet,
        })),
      },
    });
  }

  return grounded;
}

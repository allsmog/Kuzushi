import { createHash } from "node:crypto";
import type {
  SystemsProvenanceChain,
  SystemsProvenanceChainRole,
  SystemsProvenanceChainStatus,
  SystemsProvenanceChainStep,
  SystemsProvenanceFact,
  SystemsProvenanceFactKind,
  SystemsProvenanceState,
  SystemsProvenanceSummary,
} from "./types.js";

const REQUIRED_ROLES: SystemsProvenanceChainRole[] = ["origin", "alias", "write", "failure"];

export function buildProvenanceChains(args: {
  surfaceId: string;
  facts: SystemsProvenanceFact[];
  summaries: SystemsProvenanceSummary[];
  limit: number;
}): SystemsProvenanceChain[] {
  const { surfaceId, facts, summaries, limit } = args;
  if (limit <= 0 || (facts.length === 0 && summaries.length === 0)) return [];

  const steps = compactSteps([
    selectRoleStep("origin", facts, summaries),
    selectRoleStep("transport", facts, summaries),
    selectRoleStep("alias", facts, summaries),
    selectRoleStep("write", facts, summaries),
    selectRoleStep("validation", facts, summaries),
    selectRoleStep("failure", facts, summaries),
    selectGuardStep(facts, summaries),
  ]);
  if (steps.length === 0) return [];

  const guard = steps.find((step) => step.role === "guard");
  const missingRoles = REQUIRED_ROLES.filter((role) => !steps.some((step) => step.role === role));
  const status: SystemsProvenanceChainStatus = guard
    ? "blocked-by-guard"
    : missingRoles.length === 0
      ? "complete"
      : "partial";
  const score = scoreChain(steps, status, missingRoles.length);
  const narrative = buildNarrative(status, steps, missingRoles);

  return [
    {
      id: createHash("sha256")
        .update(
          `${surfaceId}|${steps.map((step) => `${step.role}:${step.filePath}:${step.line}`).join("|")}`,
        )
        .digest("hex"),
      status,
      score,
      steps,
      missingRoles,
      guardSummary: guard ? `${guard.kind}@${guard.filePath}:${guard.line}` : undefined,
      narrative,
    },
  ].slice(0, limit);
}

function selectRoleStep(
  role: SystemsProvenanceChainRole,
  facts: SystemsProvenanceFact[],
  summaries: SystemsProvenanceSummary[],
): SystemsProvenanceChainStep | undefined {
  const fact = selectFactForRole(role, facts);
  if (fact) return stepFromFact(role, fact);

  for (const summary of summaries) {
    const evidence = selectSummaryEvidenceForRole(role, summary);
    if (!evidence) continue;
    return {
      filePath: evidence.filePath,
      line: evidence.line,
      snippet: evidence.snippet,
      reason: evidence.reason,
      role,
      state: stateForRole(role, summary.states),
      kind: kindForRole(role, summary.factKinds),
      resourceFamily: summary.resourceFamilies[0] ?? "unknown",
      functionName: summary.functionName,
    };
  }
  return undefined;
}

function selectGuardStep(
  facts: SystemsProvenanceFact[],
  summaries: SystemsProvenanceSummary[],
): SystemsProvenanceChainStep | undefined {
  const fact = facts.find((entry) => entry.strength === "hard-guard");
  if (fact) return stepFromFact("guard", fact);

  const summary = summaries.find(
    (entry) => entry.aliasBehavior === "breaks-alias" || entry.hardGuards.length > 0,
  );
  const evidence = summary?.evidence.find((entry) =>
    /hard-guard|SAFE_COUNTEREXAMPLE|PRIVATE_OWNED/.test(entry.reason ?? ""),
  );
  if (!summary || !evidence) return undefined;
  return {
    filePath: evidence.filePath,
    line: evidence.line,
    snippet: evidence.snippet,
    reason: evidence.reason,
    role: "guard",
    state: summary.states.includes("PRIVATE_OWNED") ? "PRIVATE_OWNED" : "SAFE_COUNTEREXAMPLE",
    kind: summary.factKinds.includes("private-copy-guard")
      ? "private-copy-guard"
      : summary.factKinds.includes("rollback-guard")
        ? "rollback-guard"
        : "nonalias-guard",
    resourceFamily: summary.resourceFamilies[0] ?? "guard",
    functionName: summary.functionName,
  };
}

function selectFactForRole(
  role: SystemsProvenanceChainRole,
  facts: SystemsProvenanceFact[],
): SystemsProvenanceFact | undefined {
  const candidates = facts
    .filter((fact) => factMatchesRole(role, fact))
    .sort(
      (left, right) =>
        roleFactWeight(role, right) - roleFactWeight(role, left) || left.line - right.line,
    );
  return candidates[0];
}

function factMatchesRole(role: SystemsProvenanceChainRole, fact: SystemsProvenanceFact): boolean {
  switch (role) {
    case "origin":
      return (
        fact.kind === "shared-origin" ||
        fact.state === "FILE_BACKED_SHARED" ||
        fact.state === "PIPE_PAGE_SHARED" ||
        fact.state === "ITER_SHARED"
      );
    case "transport":
      return (
        fact.kind === "alias-preserving-transport" ||
        fact.kind === "iterator-propagation" ||
        fact.kind === "scatterlist-alias"
      );
    case "alias":
      return (
        fact.kind === "request-alias" ||
        fact.state === "REQ_ALIAS_MAY" ||
        fact.state === "REQ_ALIAS_MUST"
      );
    case "write":
      return fact.kind === "write-through-shared" || fact.state === "MUTATED_SHARED";
    case "validation":
      return fact.kind === "validation-before-trust" || fact.state === "VALIDATION_PENDING";
    case "failure":
      return fact.kind === "failure-after-mutation" || fact.state === "FAILED_AFTER_MUTATION";
    case "guard":
      return fact.strength === "hard-guard";
  }
}

function roleFactWeight(role: SystemsProvenanceChainRole, fact: SystemsProvenanceFact): number {
  if (role === "alias" && fact.state === "REQ_ALIAS_MUST") return 10;
  if (role === "origin" && fact.state === "FILE_BACKED_SHARED") return 9;
  if (role === "origin" && fact.state === "PIPE_PAGE_SHARED") return 8;
  if (role === "guard" && fact.kind === "private-copy-guard") return 9;
  if (fact.strength === "hard-guard") return 8;
  if (fact.strength === "strong") return 6;
  return 3;
}

function selectSummaryEvidenceForRole(
  role: SystemsProvenanceChainRole,
  summary: SystemsProvenanceSummary,
) {
  if (role === "alias" && summary.aliasBehavior !== "creates-alias") return undefined;
  if (role === "write" && !summary.writesThroughSharedAlias) return undefined;
  if (role === "failure" && !summary.validationFailureAfterMutation) return undefined;
  if (
    role === "origin" &&
    !summary.factKinds.some((kind) =>
      ["shared-origin", "alias-preserving-transport", "iterator-propagation"].includes(kind),
    )
  ) {
    return undefined;
  }
  if (
    role === "transport" &&
    !summary.factKinds.some((kind) =>
      ["alias-preserving-transport", "iterator-propagation", "scatterlist-alias"].includes(kind),
    )
  ) {
    return undefined;
  }
  if (role === "validation" && !summary.factKinds.includes("validation-before-trust")) {
    return undefined;
  }
  return (
    summary.evidence.find((entry) =>
      roleEvidencePattern(role).test(`${entry.reason ?? ""} ${entry.snippet}`),
    ) ?? summary.evidence[0]
  );
}

function roleEvidencePattern(role: SystemsProvenanceChainRole): RegExp {
  switch (role) {
    case "origin":
      return /shared-origin|alias-preserving-transport|iterator-propagation|PIPE_PAGE_SHARED|FILE_BACKED_SHARED|ITER_SHARED/;
    case "transport":
      return /alias-preserving-transport|iterator-propagation|scatterlist-alias|PIPE_PAGE_SHARED|ITER_SHARED|SG_SHARED/;
    case "alias":
      return /request-alias|REQ_ALIAS/;
    case "write":
      return /write-through-shared|MUTATED_SHARED/;
    case "validation":
      return /validation-before-trust|VALIDATION_PENDING/;
    case "failure":
      return /failure-after-mutation|FAILED_AFTER_MUTATION/;
    case "guard":
      return /hard-guard|SAFE_COUNTEREXAMPLE|PRIVATE_OWNED/;
  }
}

function stepFromFact(
  role: SystemsProvenanceChainRole,
  fact: SystemsProvenanceFact,
): SystemsProvenanceChainStep {
  return {
    filePath: fact.filePath,
    line: fact.line,
    snippet: fact.snippet,
    reason: fact.reason,
    role,
    state: fact.state,
    kind: fact.kind,
    resourceFamily: fact.resourceFamily,
    symbol: fact.symbol,
  };
}

function stateForRole(
  role: SystemsProvenanceChainRole,
  states: SystemsProvenanceState[],
): SystemsProvenanceState {
  const preferred: Record<SystemsProvenanceChainRole, SystemsProvenanceState[]> = {
    origin: ["FILE_BACKED_SHARED", "PIPE_PAGE_SHARED", "ITER_SHARED"],
    transport: ["PIPE_PAGE_SHARED", "ITER_SHARED", "SG_SHARED"],
    alias: ["REQ_ALIAS_MUST", "REQ_ALIAS_MAY"],
    write: ["MUTATED_SHARED"],
    validation: ["VALIDATION_PENDING"],
    failure: ["FAILED_AFTER_MUTATION"],
    guard: ["SAFE_COUNTEREXAMPLE", "PRIVATE_OWNED"],
  };
  return (
    preferred[role].find((state) => states.includes(state)) ?? states[0] ?? "SAFE_COUNTEREXAMPLE"
  );
}

function kindForRole(
  role: SystemsProvenanceChainRole,
  kinds: SystemsProvenanceFactKind[],
): SystemsProvenanceFactKind {
  const preferred: Record<SystemsProvenanceChainRole, SystemsProvenanceFactKind[]> = {
    origin: ["shared-origin", "alias-preserving-transport", "iterator-propagation"],
    transport: ["alias-preserving-transport", "iterator-propagation", "scatterlist-alias"],
    alias: ["request-alias"],
    write: ["write-through-shared"],
    validation: ["validation-before-trust"],
    failure: ["failure-after-mutation"],
    guard: ["private-copy-guard", "nonalias-guard", "rollback-guard"],
  };
  return preferred[role].find((kind) => kinds.includes(kind)) ?? kinds[0] ?? "shared-origin";
}

function compactSteps(
  steps: Array<SystemsProvenanceChainStep | undefined>,
): SystemsProvenanceChainStep[] {
  const seen = new Set<string>();
  const out: SystemsProvenanceChainStep[] = [];
  for (const step of steps) {
    if (!step) continue;
    const key = `${step.role}:${step.filePath}:${step.line}:${step.kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(step);
  }
  return out;
}

function scoreChain(
  steps: SystemsProvenanceChainStep[],
  status: SystemsProvenanceChainStatus,
  missingCount: number,
): number {
  const roleScore = steps.reduce((sum, step) => {
    switch (step.role) {
      case "origin":
      case "transport":
        return sum + 4;
      case "alias":
        return sum + (step.state === "REQ_ALIAS_MUST" ? 8 : 6);
      case "write":
      case "failure":
        return sum + 8;
      case "validation":
        return sum + 3;
      case "guard":
        return sum - 8;
      default:
        return sum;
    }
  }, 0);
  return roleScore + (status === "complete" ? 12 : 0) - missingCount * 3;
}

function buildNarrative(
  status: SystemsProvenanceChainStatus,
  steps: SystemsProvenanceChainStep[],
  missingRoles: SystemsProvenanceChainRole[],
): string {
  const ordered = steps
    .map((step) => `${step.role}:${step.state}/${step.kind}@${step.filePath}:${step.line}`)
    .join(" -> ");
  const suffix =
    status === "complete"
      ? "complete provenance chain"
      : status === "blocked-by-guard"
        ? "chain blocked by hard guard"
        : `partial chain missing ${missingRoles.join(", ") || "none"}`;
  return `${ordered || "no chain steps"} (${suffix})`;
}

export const __systemsProvenanceChainInternals = {
  buildProvenanceChains,
};

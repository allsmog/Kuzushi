import type { AgentRuntimeTool } from "../../agent-runtime/types.js";
import type { TaintIrisNextCweCatalogEntry } from "./cwe-reference.js";
import type {
  TaintIrisNextAgentTriageDecision,
  TaintIrisNextCandidate,
  TaintIrisNextCweTrack,
  TaintIrisNextEvidence,
  TaintIrisNextEvidenceLevel,
  TaintIrisNextEvidenceResult,
  TaintIrisNextLabeledSpec,
  TaintIrisNextLinkedStory,
  TaintIrisNextOutcome,
  TaintIrisNextPhaseCounts,
  TaintIrisNextPlan,
  TaintIrisNextSpecKind,
  TaintIrisNextSpecRole,
  TaintIrisNextTriageSummary,
} from "./types.js";

const CONTROL_TAINT_CLASSES = new Set([
  "authentication-bypass",
  "csrf",
  "file-upload",
  "hardcoded-credentials",
  "incorrect-authorization",
  "info-exposure",
  "missing-authorization",
  "origin-validation",
  "race-condition",
  "resource-exhaustion",
  "supply-chain",
  "toctou",
  "weak-crypto",
]);

const EVIDENCE_LEVEL_RANK: Record<TaintIrisNextEvidenceLevel, number> = {
  candidate: 0,
  linked: 1,
  path: 2,
};

export function trackForCatalogEntry(
  entry: Pick<TaintIrisNextCweCatalogEntry, "taintClass">,
): TaintIrisNextCweTrack {
  return CONTROL_TAINT_CLASSES.has(entry.taintClass) ? "control" : "taint";
}

export function trackForTaintClass(taintClass: string): TaintIrisNextCweTrack {
  return CONTROL_TAINT_CLASSES.has(taintClass) ? "control" : "taint";
}

export function buildCandidatesFromEvidence(
  plan: TaintIrisNextPlan,
  evidence: readonly TaintIrisNextEvidence[],
): TaintIrisNextCandidate[] {
  const out: TaintIrisNextCandidate[] = [];
  const perCwe = new Map<string, number>();
  const perCweRole = new Map<string, number>();
  const seen = new Set<string>();
  const perRoleCap = Math.max(2, Math.ceil(plan.caps.maxCandidatesPerCwe / 4));

  for (const item of [...evidence].sort(compareEvidenceRolePriority)) {
    if ((perCwe.get(item.cwe) ?? 0) >= plan.caps.maxCandidatesPerCwe) continue;
    const roleKey = `${item.cwe}:${item.role}`;
    if ((perCweRole.get(roleKey) ?? 0) >= perRoleCap) continue;
    const key = `${item.cwe}:${item.role}:${item.filePath}:${item.line}:${item.pattern}`;
    if (seen.has(key)) continue;
    seen.add(key);
    perCwe.set(item.cwe, (perCwe.get(item.cwe) ?? 0) + 1);
    perCweRole.set(roleKey, (perCweRole.get(roleKey) ?? 0) + 1);
    const track = item.track ?? trackForTaintClass(item.taintClass);
    const metadata = inferCandidateMetadata(item);
    out.push({
      id: `cand-${out.length + 1}`,
      cwe: item.cwe,
      taintClass: item.taintClass,
      track,
      role: item.role,
      kind: specKindForEvidence(item, track),
      pattern: item.pattern,
      filePath: item.filePath,
      line: item.line,
      snippet: item.snippet,
      language: item.language,
      confidence: item.confidence,
      catalogSignal: item.catalogSignal,
      source:
        item.source === "codeql" ? "codeql" : item.source === "context" ? "context" : "structural",
      ...metadata,
    });
  }

  return out;
}

function compareEvidenceRolePriority(
  left: TaintIrisNextEvidence,
  right: TaintIrisNextEvidence,
): number {
  const roleDelta = evidenceRolePriority(left.role) - evidenceRolePriority(right.role);
  if (roleDelta !== 0) return roleDelta;
  const cweDelta = left.cwe.localeCompare(right.cwe);
  if (cweDelta !== 0) return cweDelta;
  return left.line - right.line;
}

function evidenceRolePriority(role: TaintIrisNextEvidence["role"]): number {
  if (role === "sink") return 0;
  if (role === "source") return 1;
  if (role === "structural") return 2;
  return 3;
}

export function inferLabeledSpecsFromCandidates(
  plan: TaintIrisNextPlan,
  candidates: readonly TaintIrisNextCandidate[],
): TaintIrisNextLabeledSpec[] {
  const out: TaintIrisNextLabeledSpec[] = [];
  const seen = new Set<string>();
  const perCwe = new Map<string, number>();

  for (const candidate of candidates) {
    if ((perCwe.get(candidate.cwe) ?? 0) >= plan.caps.maxSpecsPerCwe) continue;
    const role = specRoleForCandidate(candidate);
    const apiName = apiNameFromPattern(candidate.pattern, candidate.snippet);
    const key = `${candidate.cwe}:${role}:${candidate.kind}:${apiName}:${candidate.pattern}`;
    if (seen.has(key)) continue;
    seen.add(key);
    perCwe.set(candidate.cwe, (perCwe.get(candidate.cwe) ?? 0) + 1);

    const spec: TaintIrisNextLabeledSpec = {
      id: `spec-${out.length + 1}`,
      cwe: candidate.cwe,
      taintClass: candidate.taintClass,
      track: candidate.track,
      role,
      kind: candidate.kind,
      apiName,
      pattern: candidate.pattern,
      confidence: candidate.confidence,
      rationale:
        candidate.track === "control"
          ? `Control-context spec from catalog signal ${candidate.catalogSignal}; use guard/policy analysis instead of generic taint.`
          : `IRIS-style typed spec from catalog signal ${candidate.catalogSignal}; agent may relabel source/sink/sanitizer roles.`,
      catalogSignal: candidate.catalogSignal,
    };
    if (candidate.filePath) spec.filePath = candidate.filePath;
    if (candidate.line) spec.line = candidate.line;
    if (role === "sink") spec.argumentIndex = 0;
    if (role === "source" && candidate.kind === "internal-param-source") spec.parameterIndex = 0;
    out.push(spec);
  }

  return out;
}

export function summarizeCountsByCwe(items: readonly { cwe: string }[]): TaintIrisNextPhaseCounts {
  const counts: TaintIrisNextPhaseCounts = {};
  for (const item of items) counts[item.cwe] = (counts[item.cwe] ?? 0) + 1;
  return counts;
}

export function summarizeTriage(
  triage: readonly TaintIrisNextAgentTriageDecision[],
): TaintIrisNextTriageSummary {
  const summary: TaintIrisNextTriageSummary = { finding: 0, candidate: 0, rejected: 0 };
  for (const decision of triage) summary[decision.status] += 1;
  return summary;
}

export function evidenceMeetsMinimum(
  level: TaintIrisNextEvidenceLevel,
  minimum: TaintIrisNextEvidenceLevel,
): boolean {
  return EVIDENCE_LEVEL_RANK[level] >= EVIDENCE_LEVEL_RANK[minimum];
}

export function strongestEvidenceLevelForCwe(
  cwe: string,
  evidence: readonly TaintIrisNextEvidence[],
): TaintIrisNextEvidenceLevel {
  const cweEvidence = evidence.filter((item) => item.cwe === cwe);
  if (cweEvidence.some((item) => item.evidenceLevel === "path")) return "path";
  if (cweEvidence.some((item) => item.evidenceLevel === "linked")) return "linked";
  return cweEvidence.length > 0 ? "candidate" : "candidate";
}

export function determineEvidenceOutcome(
  evidence: readonly TaintIrisNextEvidence[],
  warnings: readonly string[],
): TaintIrisNextOutcome {
  if (warnings.some((warning) => /timeout|timed out|SIGTERM/iu.test(warning))) {
    return "timeout-fallback";
  }
  if (evidence.some((item) => item.evidenceLevel === "path")) return "codeql-paths-produced";
  if (evidence.some((item) => item.evidenceLevel === "linked")) return "linked-evidence";
  if (evidence.length > 0) return "candidate-only";
  return "structural-only";
}

export function linkTaintCandidates(
  candidates: readonly TaintIrisNextCandidate[],
): TaintIrisNextLinkedStory[] {
  const stories: TaintIrisNextLinkedStory[] = [];
  const byCweFile = new Map<string, TaintIrisNextCandidate[]>();

  for (const candidate of candidates) {
    if (candidate.track !== "taint") continue;
    if (
      candidate.role !== "source" &&
      candidate.role !== "sink" &&
      candidate.role !== "sanitizer"
    ) {
      continue;
    }
    const key = `${candidate.cwe}:${candidate.filePath}`;
    const group = byCweFile.get(key) ?? [];
    group.push(candidate);
    byCweFile.set(key, group);
  }

  for (const items of byCweFile.values()) {
    const sources = items.filter((item) => item.role === "source");
    const sinks = items.filter((item) => item.role === "sink");
    const sanitizers = items.filter((item) => item.role === "sanitizer");
    for (const source of sources) {
      for (const sink of sinks) {
        if (Math.abs(source.line - sink.line) > 120) continue;
        const sharedTokens = sharedSemanticTokens(source.snippet, sink.snippet);
        const sameScope =
          !!source.enclosingSymbol &&
          !!sink.enclosingSymbol &&
          source.enclosingSymbol === sink.enclosingSymbol;
        if (
          source.enclosingSymbol &&
          sink.enclosingSymbol &&
          source.enclosingSymbol !== sink.enclosingSymbol
        ) {
          continue;
        }
        const closeRange = Math.abs(source.line - sink.line) <= 25;
        if (sharedTokens.length === 0 && !sameScope && !closeRange) continue;

        const betweenSanitizers = sanitizers.filter(
          (sanitizer) =>
            sanitizer.line >= Math.min(source.line, sink.line) &&
            sanitizer.line <= Math.max(source.line, sink.line),
        );
        if (betweenSanitizers.length > 0 && sharedTokens.length === 0 && !sameScope) continue;

        stories.push({
          id: `link-${stories.length + 1}`,
          cwe: source.cwe,
          taintClass: source.taintClass,
          track: "taint",
          evidenceLevel: "linked",
          filePath: source.filePath,
          language: source.language,
          sourceCandidateId: source.id,
          sinkCandidateId: sink.id,
          sourceLine: source.line,
          sinkLine: sink.line,
          sharedTokens,
          ...(sameScope && source.enclosingSymbol
            ? { enclosingSymbol: source.enclosingSymbol }
            : {}),
          ...(betweenSanitizers.length > 0
            ? { sanitizerCandidateIds: betweenSanitizers.map((candidate) => candidate.id) }
            : {}),
          rationale: renderLinkedStoryRationale(source, sink, sharedTokens, sameScope),
        });
      }
    }
  }

  return stories;
}

export function rankLinkedStoriesForReview(
  linkedStories: readonly TaintIrisNextLinkedStory[],
  candidates: readonly TaintIrisNextCandidate[],
): TaintIrisNextLinkedStory[] {
  const candidatesById = new Map(candidates.map((candidate) => [candidate.id, candidate]));
  const scored = linkedStories
    .map((story, index) => ({
      story,
      index,
      score: scoreLinkedStoryForReview(story, candidatesById),
      dedupeKey: linkedStoryDedupeKey(story, candidatesById),
    }))
    .sort((left, right) => right.score - left.score || left.index - right.index);

  const seen = new Set<string>();
  const out: TaintIrisNextLinkedStory[] = [];
  const perCwe = new Map<string, number>();
  for (const item of scored) {
    if (seen.has(item.dedupeKey)) continue;
    const cweCount = perCwe.get(item.story.cwe) ?? 0;
    if (cweCount >= 3) continue;
    seen.add(item.dedupeKey);
    perCwe.set(item.story.cwe, cweCount + 1);
    out.push(item.story);
  }
  return out;
}

export function applyLinkedStoriesToEvidence(
  evidence: readonly TaintIrisNextEvidence[],
  linkedStories: readonly TaintIrisNextLinkedStory[],
): TaintIrisNextEvidence[] {
  const linkedByEvidenceKey = new Map<string, string>();
  for (const story of linkedStories) {
    linkedByEvidenceKey.set(`${story.cwe}:${story.filePath}:${story.sourceLine}:source`, story.id);
    linkedByEvidenceKey.set(`${story.cwe}:${story.filePath}:${story.sinkLine}:sink`, story.id);
  }
  return evidence.map((item) => {
    if (item.evidenceLevel === "path") return item;
    const linkedStoryId = linkedByEvidenceKey.get(
      `${item.cwe}:${item.filePath}:${item.line}:${item.role}`,
    );
    if (linkedStoryId) return { ...item, evidenceLevel: "linked", linkedStoryId };
    return { ...item, evidenceLevel: item.evidenceLevel ?? "candidate" };
  });
}

export function createIrisEvidenceTools(
  plan: TaintIrisNextPlan,
  evidenceResult: TaintIrisNextEvidenceResult,
): AgentRuntimeTool[] {
  const candidatesById = new Map(
    evidenceResult.candidates.map((candidate) => [candidate.id, candidate]),
  );

  return [
    {
      name: "list_candidates",
      description:
        "List deterministic IRIS Next candidate APIs grouped from context, threat model, catalog signals, and structural/backend extraction.",
      parameters: objectSchema({
        cwe: stringSchema("Optional CWE id filter such as CWE-89."),
        role: stringSchema("Optional role filter: source, sink, sanitizer, or structural."),
        track: stringSchema("Optional track filter: taint or control."),
        limit: integerSchema("Maximum candidates to return."),
      }),
      execute(input) {
        const cwe = normalizeString(input["cwe"]).toUpperCase();
        const role = normalizeString(input["role"]);
        const track = normalizeString(input["track"]);
        const limit = clampInteger(input["limit"], 30, 1, 100);
        const candidates = evidenceResult.candidates
          .filter((candidate) => !cwe || candidate.cwe === cwe)
          .filter((candidate) => !role || candidate.role === role)
          .filter((candidate) => !track || candidate.track === track)
          .slice(0, limit);
        return json({
          phase: "candidate-extraction",
          count: candidates.length,
          total: evidenceResult.candidates.length,
          candidateCounts: evidenceResult.candidateCounts,
          linkedStoryCount: evidenceResult.linkedStoryCount,
          candidates,
        });
      },
    },
    {
      name: "get_candidate_context",
      description:
        "Return one candidate and nearby same-file evidence rows so the agent can inspect source/sink/guard context without broad repo search.",
      parameters: objectSchema({
        candidateId: stringSchema("Candidate id returned by list_candidates."),
      }),
      execute(input) {
        const id = normalizeString(input["candidateId"] ?? input["candidate_id"]);
        const candidate = candidatesById.get(id);
        if (!candidate) return json({ error: `candidate not found: ${id}` });
        const nearby = evidenceResult.evidence
          .filter(
            (item) =>
              item.filePath === candidate.filePath && Math.abs(item.line - candidate.line) <= 20,
          )
          .slice(0, 20);
        return json({ phase: "candidate-extraction", candidate, nearby });
      },
    },
    {
      name: "label_taint_specs",
      description:
        "Validate or inspect IRIS-style typed specs: internal parameter source, external return source, external argument sink, sanitizer, propagator, or control guard.",
      parameters: objectSchema({
        cwe: stringSchema("Optional CWE id filter."),
        limit: integerSchema("Maximum labeled specs to return."),
      }),
      execute(input) {
        const cwe = normalizeString(input["cwe"]).toUpperCase();
        const limit = clampInteger(input["limit"], 40, 1, 120);
        const specs = evidenceResult.labeledSpecs
          .filter((spec) => !cwe || spec.cwe === cwe)
          .slice(0, limit);
        return json({
          phase: "spec-inference",
          total: evidenceResult.labeledSpecs.length,
          labeledSpecCounts: evidenceResult.labeledSpecCounts,
          specs,
        });
      },
    },
    {
      name: "run_backend_query",
      description:
        "Return the already-run deterministic backend query summary and generated artifacts. This V1 tool is read-only and does not start new scans during the agent loop.",
      parameters: objectSchema({
        cwe: stringSchema("Optional CWE id filter."),
      }),
      execute(input) {
        const cwe = normalizeString(input["cwe"]).toUpperCase();
        const pathEvidence = evidenceResult.evidence
          .filter((item) => item.evidenceLevel === "path")
          .filter((item) => !cwe || item.cwe === cwe);
        return json({
          phase: "path-detection",
          backend: plan.backend.selected,
          tool: evidenceResult.tool,
          backendPathCount: evidenceResult.backendPathCount,
          linkedStoryCount: evidenceResult.linkedStoryCount,
          pathEvidence,
          artifacts: evidenceResult.artifacts ?? null,
          warnings: evidenceResult.warnings,
        });
      },
    },
    {
      name: "get_path_context",
      description:
        "Return path or linked source-to-sink/control evidence for a CWE, grouped for contextual false-positive triage.",
      parameters: objectSchema({
        cwe: stringSchema("CWE id such as CWE-89."),
        minEvidenceLevel: stringSchema("candidate, linked, or path."),
      }),
      execute(input) {
        const cwe = normalizeString(input["cwe"]).toUpperCase();
        const minimum = normalizeEvidenceLevel(
          input["minEvidenceLevel"] ?? input["min_evidence_level"],
        );
        const items = evidenceResult.evidence
          .filter((item) => !cwe || item.cwe === cwe)
          .filter((item) => evidenceMeetsMinimum(item.evidenceLevel ?? "candidate", minimum))
          .slice(0, 80);
        const linkedStories = evidenceResult.linkedStories
          .filter((story) => !cwe || story.cwe === cwe)
          .slice(0, 40);
        return json({
          phase: "contextual-triage",
          cwe: cwe || "all",
          minEvidenceLevel: minimum,
          linkedStories,
          evidence: items,
        });
      },
    },
    {
      name: "record_triage",
      description:
        "Validate and echo a contextual triage decision. Use this to keep finding/candidate/rejected rationales explicit before final JSON.",
      parameters: objectSchema({
        status: stringSchema("finding, candidate, or rejected."),
        cwe: stringSchema("CWE id."),
        evidenceLevel: stringSchema("candidate, linked, or path."),
        rationale: stringSchema("Brief rationale."),
      }),
      execute(input) {
        const status = normalizeTriageStatus(input["status"]);
        const cwe = normalizeString(input["cwe"]).toUpperCase();
        const evidenceLevel = normalizeEvidenceLevel(
          input["evidenceLevel"] ?? input["evidence_level"],
        );
        return json({
          phase: "contextual-triage",
          accepted: !!status && /^CWE-\d+$/u.test(cwe),
          decision: {
            status: status || "rejected",
            cwe,
            evidenceLevel,
            rationale: normalizeString(input["rationale"]),
          },
        });
      },
    },
  ];
}

function specKindForEvidence(
  item: Pick<TaintIrisNextEvidence, "role" | "pattern" | "snippet">,
  track: TaintIrisNextCweTrack,
): TaintIrisNextSpecKind {
  if (track === "control") return item.role === "sanitizer" ? "guard" : "control-context";
  if (item.role === "source") {
    return /return|response|fetch|request|client/iu.test(item.pattern)
      ? "external-return-source"
      : "internal-param-source";
  }
  if (item.role === "sink") return "external-arg-sink";
  if (item.role === "sanitizer") return "sanitizer";
  return "propagator";
}

function specRoleForCandidate(candidate: TaintIrisNextCandidate): TaintIrisNextSpecRole {
  if (candidate.role === "source") return "source";
  if (candidate.role === "sink") return "sink";
  if (candidate.role === "sanitizer") return "sanitizer";
  return candidate.track === "control" ? "sanitizer" : "propagator";
}

function apiNameFromPattern(pattern: string, snippet: string): string {
  const normalized = pattern
    .replace(/[()[\]{}'"`]/gu, "")
    .replace(/^\.+/u, "")
    .replace(/\.+$/u, "")
    .trim();
  if (/^[\w$./:-]{3,}$/u.test(normalized)) return normalized.slice(0, 80);
  const snippetMatch = snippet.match(/\b([A-Za-z_][\w.:-]{2,})\s*\(/u);
  return (snippetMatch?.[1] ?? pattern).slice(0, 80);
}

function inferCandidateMetadata(item: TaintIrisNextEvidence): Partial<TaintIrisNextCandidate> {
  const callExpression = item.callExpression ?? extractCallExpression(item.snippet);
  const assignedVariable = item.assignedVariable ?? extractAssignedVariable(item.snippet);
  const receiver = item.receiver ?? extractReceiver(callExpression);
  const argumentIndex = item.argumentIndex ?? inferArgumentIndex(item.snippet, item.pattern);
  const nearbySanitizers = item.nearbySanitizers;
  return {
    ...(item.enclosingSymbol ? { enclosingSymbol: item.enclosingSymbol } : {}),
    ...(callExpression ? { callExpression } : {}),
    ...(assignedVariable ? { assignedVariable } : {}),
    ...(receiver ? { receiver } : {}),
    ...(argumentIndex !== undefined ? { argumentIndex } : {}),
    ...(nearbySanitizers && nearbySanitizers.length > 0 ? { nearbySanitizers } : {}),
  };
}

function extractCallExpression(snippet: string): string | undefined {
  const call = snippet.match(/([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\([^)]{0,180}\)/u);
  return call?.[0]?.trim();
}

function extractAssignedVariable(snippet: string): string | undefined {
  const match = snippet.match(/(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*(?::=\s*|=\s*)/u);
  return match?.[1];
}

function extractReceiver(callExpression: string | undefined): string | undefined {
  const receiver = callExpression?.match(/^([A-Za-z_$][\w$]*)\./u);
  return receiver?.[1];
}

function inferArgumentIndex(snippet: string, pattern: string): number | undefined {
  const callStart = snippet.indexOf("(");
  const callEnd = snippet.lastIndexOf(")");
  if (callStart < 0 || callEnd <= callStart) return undefined;
  const args = snippet.slice(callStart + 1, callEnd).split(",");
  const patternToken = normalizeToken(pattern);
  if (!patternToken) return undefined;
  const index = args.findIndex((arg) => arg.toLowerCase().includes(patternToken));
  return index >= 0 ? index : undefined;
}

function sharedSemanticTokens(left: string, right: string): string[] {
  const leftTokens = semanticTokens(left);
  const rightTokens = semanticTokens(right);
  return [...leftTokens].filter((token) => rightTokens.has(token)).slice(0, 8);
}

function semanticTokens(value: string): Set<string> {
  const tokens = new Set<string>();
  for (const token of value.toLowerCase().match(/[a-z_][a-z0-9_]{2,}/gu) ?? []) {
    if (STOP_TOKENS.has(token)) continue;
    tokens.add(token);
  }
  return tokens;
}

function normalizeToken(value: string): string | undefined {
  const token = value.toLowerCase().match(/[a-z_][a-z0-9_]{2,}/u)?.[0];
  return token && !STOP_TOKENS.has(token) ? token : undefined;
}

function renderLinkedStoryRationale(
  source: TaintIrisNextCandidate,
  sink: TaintIrisNextCandidate,
  sharedTokens: readonly string[],
  sameScope: boolean,
): string {
  const link =
    sharedTokens.length > 0 ? `shared token(s): ${sharedTokens.join(", ")}` : "line-local flow";
  const scope = sameScope && source.enclosingSymbol ? ` in ${source.enclosingSymbol}` : "";
  return `${source.cwe} structural source at ${source.filePath}:${source.line} is near sink at ${sink.line}${scope}; ${link}.`;
}

function scoreLinkedStoryForReview(
  story: TaintIrisNextLinkedStory,
  candidatesById: ReadonlyMap<string, TaintIrisNextCandidate>,
): number {
  const source = candidatesById.get(story.sourceCandidateId);
  const sink = candidatesById.get(story.sinkCandidateId);
  const sinkText = `${sink?.pattern ?? ""} ${sink?.catalogSignal ?? ""} ${sink?.snippet ?? ""}`;
  const sourceText = `${source?.pattern ?? ""} ${source?.catalogSignal ?? ""} ${source?.snippet ?? ""}`;
  let score = cweRiskPriority(story.cwe);
  score += story.sharedTokens.length > 0 ? 120 + story.sharedTokens.length * 8 : 0;
  score += story.enclosingSymbol ? 80 : 0;
  score += Math.max(0, 60 - Math.abs(story.sinkLine - story.sourceLine));
  score += confidenceScore(source?.confidence) + confidenceScore(sink?.confidence);
  score += sinkDangerBonus(story.cwe, sinkText);
  score += sourceTrustBonus(sourceText);
  if (story.sanitizerCandidateIds && story.sanitizerCandidateIds.length > 0) {
    score -= 120;
  }
  if (isWeakParameterizedLogger(story.cwe, sinkText)) {
    score -= 450;
  }
  if (/line-local flow/iu.test(story.rationale) && story.sharedTokens.length === 0) {
    score -= 90;
  }
  return score;
}

function cweRiskPriority(cwe: string): number {
  switch (cwe) {
    case "CWE-78":
      return 1000;
    case "CWE-77":
      return 960;
    case "CWE-94":
    case "CWE-95":
      return 930;
    case "CWE-89":
    case "CWE-943":
      return 900;
    case "CWE-918":
      return 860;
    case "CWE-22":
    case "CWE-73":
      return 820;
    case "CWE-502":
    case "CWE-611":
      return 720;
    case "CWE-79":
    case "CWE-113":
    case "CWE-601":
      return 620;
    case "CWE-117":
      return 180;
    default:
      return 480;
  }
}

function sinkDangerBonus(cwe: string, text: string): number {
  let score = 0;
  if (/\bshell\s*=\s*true\b|\/bin\/(?:ba)?sh\b|(?:^|\W)-c(?:\W|$)/iu.test(text)) score += 350;
  if (/\bsubprocess\.(?:Popen|call|run)\b|\bos\.system\b|\bexec(?:v|l|ve)?\b/iu.test(text))
    score += 220;
  if (/\bdocker(?:-compose)?\b.*\{|\bf["'`][^"'`]*\bdocker\b/iu.test(text)) score += 160;
  if (/\b(?:pickle\.loads|yaml\.load|marshal\.loads|eval|exec)\b/iu.test(text)) score += 170;
  if (/\b(?:open|readFile|writeFile)\s*\(/iu.test(text)) score += 120;
  if (/\b(?:query|execute|raw|whereRaw)\s*\(/iu.test(text)) score += 120;
  if (
    cwe === "CWE-117" &&
    /\blogger\.(?:debug|info|warn|warning|error|exception)\s*\(/iu.test(text)
  ) {
    score -= 80;
  }
  return score;
}

function sourceTrustBonus(text: string): number {
  if (
    /\b(?:req|request|params|query|body|headers|cookies|argv|env|stdin|input|command|url|path)\b/iu.test(
      text,
    )
  ) {
    return 80;
  }
  return 0;
}

function confidenceScore(confidence: TaintIrisNextCandidate["confidence"] | undefined): number {
  if (confidence === "high") return 80;
  if (confidence === "medium") return 40;
  return 0;
}

function isWeakParameterizedLogger(cwe: string, text: string): boolean {
  if (cwe !== "CWE-117") return false;
  if (!/\blogger\.(?:debug|info|warn|warning|error|exception)\s*\(/iu.test(text)) return false;
  if (/[\r\n]|\\r|\\n|\+\s*\w|\bf["']/u.test(text)) return false;
  return /%[sdjor]|,\s*[A-Za-z_]/u.test(text);
}

function linkedStoryDedupeKey(
  story: TaintIrisNextLinkedStory,
  candidatesById: ReadonlyMap<string, TaintIrisNextCandidate>,
): string {
  if (story.cwe === "CWE-117") {
    return [story.cwe, story.filePath, story.enclosingSymbol ?? story.sourceLine].join(":");
  }
  const sink = candidatesById.get(story.sinkCandidateId);
  const sinkShape = sink?.snippet.replace(/\s+/gu, " ").slice(0, 80) ?? story.sinkLine;
  return [
    story.cwe,
    story.filePath,
    story.enclosingSymbol ?? "",
    story.sourceLine,
    story.sinkLine,
    sinkShape,
  ].join(":");
}

const STOP_TOKENS = new Set([
  "and",
  "args",
  "body",
  "const",
  "data",
  "def",
  "for",
  "from",
  "get",
  "let",
  "new",
  "req",
  "request",
  "res",
  "return",
  "self",
  "shell",
  "true",
  "var",
]);

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeTriageStatus(value: unknown): TaintIrisNextAgentTriageDecision["status"] | "" {
  const normalized = normalizeString(value);
  if (normalized === "finding" || normalized === "candidate" || normalized === "rejected") {
    return normalized;
  }
  return "";
}

function normalizeEvidenceLevel(value: unknown): TaintIrisNextEvidenceLevel {
  const normalized = normalizeString(value);
  if (normalized === "path" || normalized === "linked" || normalized === "candidate") {
    return normalized;
  }
  return "candidate";
}

function clampInteger(value: unknown, fallback: number, minimum: number, maximum: number): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(maximum, Math.max(minimum, Math.floor(numeric)));
}

function objectSchema(properties: Record<string, unknown>): Record<string, unknown> {
  return {
    type: "object",
    additionalProperties: false,
    properties,
  };
}

function stringSchema(description: string): Record<string, unknown> {
  return { type: "string", description };
}

function integerSchema(description: string): Record<string, unknown> {
  return { type: "integer", minimum: 1, description };
}

function json(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

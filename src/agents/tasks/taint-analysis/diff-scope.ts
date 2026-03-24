import type { Finding } from "../../../scanners/types.js";
import { getLogger } from "../../../logger.js";
import {
  TAINT_ANALYSIS_PASS_IDS,
  type DiffScope,
  type TaintAnalysisLabelsDocument,
  type TaintAnalysisPassId,
} from "./types.js";

const log = getLogger("taint-analysis-run");

/**
 * Taint-support artifact file patterns that, when changed, should force a
 * full analysis run regardless of which passes the diff would otherwise
 * narrow to. This covers CodeQL libraries, query templates, and label
 * definitions that affect all passes.
 */
const TAINT_SUPPORT_ARTIFACT_PATTERNS = [
  "/iris/",
  "/augur/",
  ".qll",
  ".ql.tmpl",
  "labels.json",
  "TAINT_MODEL.json",
];

/**
 * After labels are available, narrow the preflight `DiffScope.affectedPassIds`
 * by intersecting `changedFiles` with the file locations referenced in labeled
 * source/sink/summary entries. If any changed file touches taint support
 * artifacts, fall back to full analysis.
 */
export function narrowDiffScope(
  preflightScope: DiffScope | undefined,
  labels: TaintAnalysisLabelsDocument,
): DiffScope | undefined {
  if (!preflightScope) {
    return undefined;
  }

  if (preflightScope.fellBackToFull) {
    return preflightScope;
  }

  const changedSet = new Set(preflightScope.changedFiles);
  for (const changedFile of changedSet) {
    if (TAINT_SUPPORT_ARTIFACT_PATTERNS.some((pattern) => changedFile.includes(pattern))) {
      log.info(
        { changedFile },
        "Changed file matches taint support artifact pattern; forcing full analysis",
      );
      return {
        ...preflightScope,
        fellBackToFull: true,
        fallbackReason: `taint_support_artifact_changed: ${changedFile}`,
      };
    }
  }

  const affectedPassIds = new Set<TaintAnalysisPassId>();
  for (const pass of labels.passes) {
    for (const entry of pass.entries) {
      if (entry.classification === "fp" || entry.role === "none") {
        continue;
      }
      if (changedSet.has(entry.location.file)) {
        affectedPassIds.add(pass.pass_id);
        break;
      }
    }
  }

  if (affectedPassIds.size === 0) {
    log.info(
      { affectedPassCount: preflightScope.affectedPassIds.length },
      "Diff narrowing found no affected passes from labels; keeping preflight scope",
    );
    return preflightScope;
  }

  const narrowed = [...affectedPassIds].sort((a, b) => a - b) as TaintAnalysisPassId[];
  log.info(
    {
      previousAffectedPassCount: preflightScope.affectedPassIds.length,
      narrowedAffectedPassCount: narrowed.length,
      affectedPassIds: narrowed,
    },
    "Narrowed diff-aware taint analysis scope",
  );

  return {
    ...preflightScope,
    affectedPassIds: narrowed,
  };
}

export function extractPassId(ruleId: string): TaintAnalysisPassId | undefined {
  const match = ruleId.match(/taint-analysis\/pass(\d+)\//i);
  if (!match) {
    return undefined;
  }

  const id = Number.parseInt(match[1], 10);
  return TAINT_ANALYSIS_PASS_IDS.has(id) ? id as TaintAnalysisPassId : undefined;
}

export function mergeBaselineTaintFindings(
  cachedFindings: Finding[],
  rerunFindings: Finding[],
  affectedPassIds: TaintAnalysisPassId[],
): Finding[] {
  if (cachedFindings.length === 0) {
    return rerunFindings;
  }

  const affectedPassSet = new Set<TaintAnalysisPassId>(affectedPassIds);
  const merged = [
    ...cachedFindings.filter((finding) => {
      const passId = extractPassId(finding.ruleId);
      return passId == null || !affectedPassSet.has(passId);
    }),
    ...rerunFindings,
  ];

  const deduped = new Map<string, Finding>();
  for (const finding of merged) {
    deduped.set(finding.fingerprint, finding);
  }
  return [...deduped.values()];
}

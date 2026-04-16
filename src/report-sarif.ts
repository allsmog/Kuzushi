import type Database from "better-sqlite3";
import type { PipelineStats } from "./bus/events.js";
import { getActionableFindings } from "./store.js";
import { loadThreatModelDocument } from "./threat-model-renderer.js";
import { isRecord } from "./utils.js";

interface RunMetaRow {
  startedAt?: string;
  configJson?: string;
  findingsJson?: string;
}

interface ParsedRunConfig {
  model?: string;
  tasks: string[];
}

interface CheckpointFindingMeta {
  message?: string;
  cweTags: string[];
}

type SarifLevel = "error" | "warning" | "note";

interface RuleDraft {
  id: string;
  level: SarifLevel;
  tags: Set<string>;
}

export function generateSarifReport(
  db: Database.Database,
  repo: string,
  stats: Partial<PipelineStats>,
  runId: string,
  fingerprints?: string[],
  repoRoot?: string,
): string {
  const findings = getActionableFindings(db, repo, { includeFalsePositives: true, fingerprints });

  const verdictCounts = { tp: 0, fp: 0, needs_review: 0, by_design: 0 };
  let exploitable = 0;
  let notExploitable = 0;
  for (const f of findings) {
    if (f.verdict === "tp") verdictCounts.tp++;
    else if (f.verdict === "fp") verdictCounts.fp++;
    else if (f.verdict === "by_design") verdictCounts.by_design++;
    else verdictCounts.needs_review++;
    if (f.verifyExploitable === 1) exploitable++;
    else if (f.verifyExploitable === 0) notExploitable++;
  }
  const verificationCounts = { exploitable, notExploitable };
  const triageCostUsd = stats.totalCostUsd ?? 0;
  const verifyCostUsd =
    stats.verifyCostUsd ?? findings.reduce((sum, f) => sum + (f.verifyCostUsd ?? 0), 0);
  const pocHarnessCostUsd =
    stats.pocHarnessCostUsd ?? findings.reduce((sum, f) => sum + (f.pocHarnessCostUsd ?? 0), 0);

  const runMeta = db
    .prepare(`
    SELECT
      started_at as startedAt,
      config_json as configJson,
      findings_json as findingsJson
    FROM pipeline_runs
    WHERE run_id = ?
    LIMIT 1
  `)
    .get(runId) as RunMetaRow | undefined;

  const runConfig = parseRunConfig(runMeta?.configJson);
  const checkpointMetaByFingerprint = parseCheckpointFindingMeta(runMeta?.findingsJson);
  const rulesById = new Map<string, RuleDraft>();

  const results = findings.map((finding) => {
    const level = toSarifLevel(finding.severity);
    const checkpointMeta = checkpointMetaByFingerprint.get(finding.fingerprint);
    const cweTags = checkpointMeta?.cweTags ?? [];
    upsertRule(rulesById, finding.ruleId, level, cweTags);

    const messageText = finding.message || checkpointMeta?.message || finding.ruleId;
    const result: Record<string, unknown> = {
      ruleId: finding.ruleId,
      level,
      message: {
        text: messageText,
      },
      locations: [buildSarifLocation(finding.filePath, finding.startLine)],
      properties: {
        verdict: finding.verdict,
        confidence: finding.confidence,
        rationale: finding.rationale,
        adjustedScore: finding.adjustedScore ?? undefined,
        proofState: finding.proofState ?? undefined,
        engineProvenance: finding.engineProvenance?.length ? finding.engineProvenance : undefined,
        corroboratingSignalCount: finding.corroboratingSignals.length || undefined,
        corroboratingSignals:
          finding.corroboratingSignals.length > 0 ? finding.corroboratingSignals : undefined,
        suppressionReasons:
          finding.suppressionReasons.length > 0 ? finding.suppressionReasons : undefined,
        exploitable: toExploitableFlag(finding.verifyExploitable),
        pocPayload: finding.verifyPocPayload ?? undefined,
        pocRunVerdict: finding.pocRunVerdict ?? undefined,
        pocRunDurationMs: finding.pocRunDurationMs ?? undefined,
        codeCitations: finding.codeCitations?.length ? finding.codeCitations : undefined,
        attackPath: finding.attackPath ?? undefined,
        assumptions: finding.assumptions?.length ? finding.assumptions : undefined,
        controls: finding.controls?.length ? finding.controls : undefined,
        blindspots: finding.blindspots?.length ? finding.blindspots : undefined,
        sourceThreatIds: finding.sourceThreatIds?.length ? finding.sourceThreatIds : undefined,
        blame: finding.blame ?? undefined,
        introducedIn: finding.introducedIn ?? undefined,
      },
    };

    if (finding.taintPath && finding.taintPath.length > 0) {
      result["codeFlows"] = [
        {
          threadFlows: [
            {
              locations: finding.taintPath.map((step, index) => ({
                location: buildSarifLocation(step.filePath, step.line),
                message: {
                  text: step.message || `taint step ${index + 1}`,
                },
              })),
            },
          ],
        },
      ];
    }

    if (finding.fixPatch) {
      result["fixes"] = [
        {
          description: {
            text: finding.fixPatch,
          },
        },
      ];
    }

    if (finding.verdict === "fp") {
      result["suppressions"] = [
        {
          kind: "inSource",
          justification: finding.rationale || "Marked false positive during triage.",
        },
      ];
    }

    return result;
  });

  const rules = [...rulesById.values()]
    .sort((a, b) => a.id.localeCompare(b.id))
    .map((rule) => {
      const serialized: Record<string, unknown> = {
        id: rule.id,
        shortDescription: {
          text: rule.id,
        },
        defaultConfiguration: {
          level: rule.level,
        },
      };

      if (rule.tags.size > 0) {
        serialized["properties"] = {
          tags: [...rule.tags].sort((a, b) => a.localeCompare(b)),
        };
      }

      return serialized;
    });

  const threatModel = repoRoot ? loadThreatModelDocument(repoRoot, runId) : null;

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "kuzushi",
            informationUri: "https://github.com/allsmog/Kuzushi",
            rules,
          },
        },
        automationDetails: {
          id: runId,
        },
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: runMeta?.startedAt ?? stats.startedAt,
            endTimeUtc: stats.completedAt,
          },
        ],
        results,
        properties: {
          repo,
          runId,
          model: runConfig.model,
          tasks: runConfig.tasks,
          threatModel: threatModel ?? undefined,
          summary: {
            totalFindings:
              stats.totalFindings ??
              verdictCounts.tp + verdictCounts.fp + verdictCounts.needs_review,
            queuedForTriage: stats.queuedForTriage ?? 0,
            skippedAlreadyTriaged: stats.skippedAlreadyTriaged ?? 0,
            skippedLowConfidence: stats.skippedLowConfidence ?? 0,
            skippedByFpFilter: stats.skippedByFpFilter ?? 0,
            softSuppressedFindings: stats.softSuppressedFindings ?? 0,
            skippedByLlmRescore: stats.skippedByLlmRescore ?? 0,
            corroboratedClusters: stats.corroboratedClusters ?? 0,
            truePositives: verdictCounts.tp,
            needsReview: verdictCounts.needs_review,
            falsePositives: verdictCounts.fp,
            exploitable: verificationCounts.exploitable,
            notExploitable: verificationCounts.notExploitable,
            triageCostUsd,
            verificationCostUsd: verifyCostUsd,
            pocHarnessGenerated: stats.pocHarnessGenerated ?? 0,
            pocHarnessSkipped: stats.pocHarnessSkipped ?? 0,
            pocHarnessErrors: stats.pocHarnessErrors ?? 0,
            pocHarnessCostUsd,
            variantFindings: stats.variantFindings ?? 0,
            variantAnalysisCostUsd: stats.variantAnalysisCostUsd ?? 0,
            totalCostUsd: triageCostUsd + verifyCostUsd + pocHarnessCostUsd,
          },
        },
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

function parseRunConfig(raw: string | undefined): ParsedRunConfig {
  if (!raw) {
    return { model: undefined, tasks: [] };
  }

  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const model = typeof parsed["model"] === "string" ? parsed["model"] : undefined;
    const tasks = Array.isArray(parsed["tasks"])
      ? parsed["tasks"].map((item) => String(item).trim()).filter(Boolean)
      : [];

    return { model, tasks };
  } catch {
    // Graceful degradation: config JSON from the DB may be corrupted or
    // written by a different schema version. Return safe defaults so SARIF
    // generation still succeeds with partial metadata.
    return { model: undefined, tasks: [] };
  }
}

function parseCheckpointFindingMeta(raw: string | undefined): Map<string, CheckpointFindingMeta> {
  const byFingerprint = new Map<string, CheckpointFindingMeta>();
  if (!raw) {
    return byFingerprint;
  }

  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return byFingerprint;
    }

    for (const item of parsed) {
      if (!isRecord(item)) {
        continue;
      }

      const fingerprint = asString(item["fingerprint"]);
      if (!fingerprint) {
        continue;
      }

      byFingerprint.set(fingerprint, {
        message: asString(item["message"]),
        cweTags: normalizeCweTags(item["cwe"]),
      });
    }
  } catch {
    // Graceful degradation: findings JSON checkpoint may be malformed.
    // Return whatever was parsed so far rather than failing the entire report.
    return byFingerprint;
  }

  return byFingerprint;
}

function normalizeCweTags(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const tags = new Set<string>();
  for (const entry of value) {
    const normalized = String(entry).trim();
    const match = normalized.match(/(\d+)/);
    if (!match) {
      continue;
    }

    tags.add(`external/cwe/cwe-${match[1]}`);
  }

  return [...tags];
}

function upsertRule(
  rulesById: Map<string, RuleDraft>,
  ruleId: string,
  level: SarifLevel,
  cweTags: string[],
): void {
  const existing = rulesById.get(ruleId);
  if (!existing) {
    rulesById.set(ruleId, {
      id: ruleId,
      level,
      tags: new Set(cweTags),
    });
    return;
  }

  if (severityRank(level) > severityRank(existing.level)) {
    existing.level = level;
  }

  for (const tag of cweTags) {
    existing.tags.add(tag);
  }
}

function severityRank(level: SarifLevel): number {
  if (level === "error") {
    return 3;
  }
  if (level === "warning") {
    return 2;
  }
  return 1;
}

function toSarifLevel(severity: string): SarifLevel {
  const normalized = severity.trim().toUpperCase();
  if (normalized === "ERROR") {
    return "error";
  }
  if (normalized === "WARNING") {
    return "warning";
  }
  return "note";
}

function buildSarifLocation(filePath: string, startLine: number): Record<string, unknown> {
  const uri = toRelativeUri(filePath);
  const _isDirectory = uri === "." || uri === "" || uri.endsWith("/");
  const physicalLocation: Record<string, unknown> = {
    artifactLocation: { uri: uri || "." },
  };
  // Always emit a region for SARIF consumer compatibility; clamp startLine >= 1 per SARIF 2.1.0 spec
  physicalLocation["region"] = { startLine: Math.max(1, startLine) };
  return { physicalLocation };
}

function toRelativeUri(filePath: string): string {
  const normalized = filePath.replace(/\\/g, "/");
  return normalized.replace(/^\/+/, "").replace(/^[A-Za-z]:\//, "");
}

function toExploitableFlag(value: number | null): boolean | undefined {
  if (value === 1) {
    return true;
  }

  if (value === 0) {
    return false;
  }

  return undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

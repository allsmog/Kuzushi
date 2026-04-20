/**
 * Full scan summary display using box-drawing sections.
 */

import { Box, Text } from "ink";
import type React from "react";
import {
  boxDivider,
  boxFooter,
  boxHeader,
  formatCost,
  formatDuration,
  miniBarChart,
  terminalCardWidth,
} from "../format.js";
import { icons } from "../icons.js";
import { Table } from "../primitives/Table.js";
import type { SummaryData } from "../state.js";
import { tokens } from "../tokens.js";
import { AttackChainDiagram } from "./AttackChainDiagram.js";
import { FindingCard } from "./FindingCard.js";
import { TrophyScreen } from "./TrophyScreen.js";

interface VerdictRow {
  label: string;
  value: string;
}

interface ScanSummaryProps {
  data: SummaryData;
}

export function ScanSummary({ data }: ScanSummaryProps): React.ReactElement {
  const width = terminalCardWidth(96, 60);
  const { verdictCounts: counts } = data;
  const total = counts.tp + counts.fp + counts.needs_review;
  const actionableCount = counts.tp + counts.needs_review;
  const riskLabel =
    data.exploitable > 0
      ? tokens.dangerStrong("Critical")
      : counts.tp > 0
        ? tokens.danger("High")
        : counts.needs_review > 0
          ? tokens.warn("Review")
          : tokens.success("Low");
  const nextAction =
    data.exploitable > 0
      ? "Fix exploitable findings first."
      : counts.tp > 0
        ? "Address confirmed true positives."
        : counts.needs_review > 0
          ? "Review undecided findings."
          : "No immediate action required.";

  const hasVerificationData =
    data.exploitable + data.notExploitable > 0 ||
    data.verifyErrors > 0 ||
    data.verificationCostUsd > 0;

  const hasPocData =
    data.pocGenerated > 0 ||
    data.pocSkipped > 0 ||
    data.pocHarnessErrors > 0 ||
    data.pocHarnessCostUsd > 0;

  const hasDynamic =
    data.dynamicConfirmed + data.dynamicInteresting + data.dynamicRejected + data.dynamicErrors > 0;

  const hasPatch =
    data.patchGenerated + data.patchVerified + data.patchFailed + data.patchErrors > 0;

  const hasIncremental = data.incrementalCachedFiles > 0 || data.incrementalRescannedFiles > 0;

  return (
    <Box flexDirection="column">
      {/* Trophy screen flushes left — handles its own ASCII box framing. */}
      <TrophyScreen data={data} />

      <Text>{""}</Text>
      <Text>{boxHeader(`${icons.complete} Scan Results`, width)}</Text>
      <Text>{""}</Text>

      {/* Indented body — every row below lands at column 2 via paddingLeft. */}
      <Box flexDirection="column" paddingLeft={2}>
        <Table<VerdictRow>
          columns={[
            { key: "label", width: 14, align: "left" },
            { key: "value", flex: 1, align: "left", truncate: "end" },
          ]}
          rows={[
            { label: "Risk", value: riskLabel },
            { label: "Actionable", value: `${actionableCount} of ${total} triaged` },
            ...(hasVerificationData
              ? [{ label: "Exploitable", value: String(data.exploitable) }]
              : []),
            { label: "Next", value: nextAction },
          ]}
          showHeader={false}
          divider={false}
          maxWidth={width - 2}
          gap={2}
        />

        {/* Failed tasks warning */}
        {data.failedTasks.length > 0 && (
          <Text>
            {tokens.danger("Scanners failed:")} {data.failedTasks.join(", ")}{" "}
            {tokens.muted("(results may be incomplete)")}
          </Text>
        )}

        {/* Degradation warnings */}
        {data.extractionDegradation && data.extractionDegradation.status !== "ok" && (
          <Text>
            {(data.extractionDegradation.status === "failed" ? tokens.danger : tokens.warn)(
              "Extraction:",
            )}{" "}
            {data.extractionDegradation.status} [{data.extractionDegradation.reasons.join(", ")}]
          </Text>
        )}
        {data.stitchDegradation && (
          <Text>
            {tokens.warn("Stitch:")} degraded [{data.stitchDegradation.reason}]
          </Text>
        )}
        {data.tiPriorDegraded && <Text>{tokens.warn("TI Prior:")} degraded</Text>}

        {/* Verdict counts — aligned via Table primitive (already inside the
          paddingLeft=2 wrapper above, no extra padding needed here). */}
        <Table<VerdictRow>
          columns={[
            { key: "label", width: 26, align: "left" },
            { key: "value", width: 8, align: "right" },
          ]}
          rows={[
            { label: tokens.muted("Total triaged"), value: String(total) },
            {
              label: tokens.dangerStrong(`${icons.error} True positives`),
              value: String(counts.tp),
            },
            {
              label: tokens.success(`${icons.success} False positives`),
              value: String(counts.fp),
            },
            {
              label: tokens.warn(`${icons.warning} Needs review`),
              value: String(counts.needs_review),
            },
          ]}
          showHeader={false}
          divider={false}
          maxWidth={width - 2}
          gap={2}
        />

        {data.triageErrors > 0 && (
          <Text>
            {tokens.danger("Triage errors:")} {data.triageErrors}
          </Text>
        )}
        {data.skippedLowConfidence > 0 && (
          <Text>
            {tokens.muted("Skipped (low confidence):")} {data.skippedLowConfidence}
          </Text>
        )}
        {data.skippedByFpFilter > 0 && (
          <Text>
            {tokens.muted("Skipped (hard exclusions):")} {data.skippedByFpFilter}
          </Text>
        )}
        {data.softSuppressedFindings > 0 && (
          <Text>
            {tokens.muted("Soft-suppressed findings:")} {data.softSuppressedFindings}
          </Text>
        )}
        {data.skippedByLlmRescore > 0 && (
          <Text>
            {tokens.muted("Skipped (LLM rescore):")} {data.skippedByLlmRescore}
          </Text>
        )}
        {data.corroboratedClusters > 0 && (
          <Text>
            {tokens.muted("Corroborated clusters:")} {data.corroboratedClusters}
          </Text>
        )}
        {(data.verifyGateAutoAccepted > 0 || data.verifyGateSkipped > 0) && (
          <>
            <Text>
              {tokens.muted("Gate auto-accepted:")} {data.verifyGateAutoAccepted}
            </Text>
            <Text>
              {tokens.muted("Gate skipped:")} {data.verifyGateSkipped}
            </Text>
          </>
        )}

        {/* Verdict distribution bar */}
        {total > 0 && (
          <>
            <Text>{""}</Text>
            {miniBarChart([
              { label: "tp", value: counts.tp, color: tokens.danger },
              { label: "fp", value: counts.fp, color: tokens.success },
              { label: "needs_review", value: counts.needs_review, color: tokens.warn },
            ]).map((line, i) => (
              <Text key={i}>{line}</Text>
            ))}
          </>
        )}

        {/* Verification section */}
        {hasVerificationData && (
          <>
            <Text>{""}</Text>
            <Text>{boxDivider(width)}</Text>
            <Text>{tokens.label("Verification")}</Text>
            <Text>
              {tokens.dangerStrong(`${icons.error} Exploitable:`)} {data.exploitable}
            </Text>
            <Text>
              {tokens.success(`${icons.success} Not exploitable:`)} {data.notExploitable}
            </Text>
            {data.verifyErrors > 0 && (
              <Text>
                {tokens.danger("Verification errors:")} {data.verifyErrors}
              </Text>
            )}
          </>
        )}

        {/* PoC section */}
        {hasPocData && (
          <>
            <Text>{""}</Text>
            <Text>{boxDivider(width)}</Text>
            <Text>{tokens.label("PoC Harnesses")}</Text>
            <Text>
              {tokens.accent(`${icons.gear} Generated:`)} {data.pocGenerated}
            </Text>
            <Text>
              {tokens.warn(`${icons.pending} Skipped:`)} {data.pocSkipped}
            </Text>
            {data.pocHarnessErrors > 0 && (
              <Text>
                {tokens.danger("Errors:")} {data.pocHarnessErrors}
              </Text>
            )}
            {data.pocOutputDir && (
              <Text>
                {tokens.muted("Output dir:")} {data.pocOutputDir}
              </Text>
            )}
          </>
        )}

        {/* Variant findings */}
        {data.variantFindings > 0 && (
          <>
            <Text>{""}</Text>
            <Text>
              {tokens.accent("Variant findings:")} {data.variantFindings}
            </Text>
          </>
        )}

        {/* Dynamic analysis */}
        {hasDynamic && (
          <>
            <Text>{""}</Text>
            <Text>{boxDivider(width)}</Text>
            <Text>{tokens.label("Dynamic Analysis")}</Text>
            <Text>
              {"    "}
              {tokens.dangerStrong(`Confirmed:`)} {data.dynamicConfirmed}
            </Text>
            <Text>
              {"    "}
              {tokens.warn(`Interesting:`)} {data.dynamicInteresting}
            </Text>
            <Text>
              {"    "}
              {tokens.success(`Rejected:`)} {data.dynamicRejected}
            </Text>
            {data.dynamicErrors > 0 && (
              <Text>
                {"    "}
                {tokens.danger("Errors:")} {data.dynamicErrors}
              </Text>
            )}
            {data.dynamicCostUsd > 0 && (
              <Text>
                {"    "}
                {tokens.muted("Cost:")} {formatCost(data.dynamicCostUsd)}
              </Text>
            )}
          </>
        )}

        {/* Incremental */}
        {hasIncremental && (
          <>
            <Text>{""}</Text>
            <Text>
              {tokens.muted("Incremental:")}{" "}
              {tokens.success(`${data.incrementalCachedFiles} cached`)},{" "}
              {data.incrementalRescannedFiles} rescanned
              {data.incrementalDepExpandedFiles > 0
                ? `, ${data.incrementalDepExpandedFiles} dependency-expanded`
                : ""}
            </Text>
          </>
        )}

        {/* Patch synthesis */}
        {hasPatch && (
          <>
            <Text>{""}</Text>
            <Text>{boxDivider(width)}</Text>
            <Text>{tokens.label("Patch Synthesis")}</Text>
            <Text>
              {"    "}
              {tokens.accent("Generated:")} {data.patchGenerated}
            </Text>
            <Text>
              {"    "}
              {tokens.success("Verified:")} {data.patchVerified} (finding eliminated after patch)
            </Text>
            {data.patchFailed > 0 && (
              <Text>
                {"    "}
                {tokens.danger("Failed:")} {data.patchFailed}
              </Text>
            )}
            {data.patchErrors > 0 && (
              <Text>
                {"    "}
                {tokens.danger("Errors:")} {data.patchErrors}
              </Text>
            )}
            {data.patchCostUsd > 0 && (
              <Text>
                {"    "}
                {tokens.muted("Cost:")} {formatCost(data.patchCostUsd)}
              </Text>
            )}
          </>
        )}

        {/* Exploit chains — flow diagram */}
        {data.exploitChains.length > 0 && (
          <>
            <Text>{""}</Text>
            <Text>{boxDivider(width)}</Text>
            <Text>{tokens.label("Exploitation Chains")}</Text>
            <Text>{""}</Text>
            {data.exploitChains.map((chain, ci) => (
              <Box key={ci} flexDirection="column">
                <AttackChainDiagram chain={chain} />
                <Text>{""}</Text>
              </Box>
            ))}
          </>
        )}

        {/* Threat model context */}
        {data.threatModelSummary && (
          <Box flexDirection="column" marginBottom={1}>
            <Text bold>Threat Model Context</Text>
            <Text>{data.threatModelSummary}</Text>
          </Box>
        )}

        {/* Actionable findings */}
        {data.actionableFindings.length > 0 && (
          <>
            <Text>{""}</Text>
            <Text>{boxDivider(width)}</Text>
            <Text>{tokens.label("Actionable Findings")}</Text>
            <Text>{""}</Text>
            {data.actionableFindings.map((f, i) => (
              <FindingCard key={i} finding={f} />
            ))}
          </>
        )}
        {data.actionableFindings.length === 0 && total > 0 && (
          <>
            <Text>{""}</Text>
            <Text>
              {tokens.successStrong(
                `${icons.success} All findings triaged as false positives. Code looks clean.`,
              )}
            </Text>
          </>
        )}

        {/* Cost summary — bar chart */}
        <Text>{""}</Text>
        <Text>{boxDivider(width)}</Text>
        <Text>{tokens.label(`Cost (${formatCost(data.triageCostUsd + data.verificationCostUsd + data.pocHarnessCostUsd + data.variantAnalysisCostUsd + data.dynamicCostUsd + data.patchCostUsd)})`)}</Text>
        <Text>{""}</Text>
        {miniBarChart(
          [
            { label: "Triage", value: data.triageCostUsd, color: tokens.accent },
            { label: "Verify", value: data.verificationCostUsd, color: tokens.danger },
            { label: "PoC", value: data.pocHarnessCostUsd, color: tokens.warn },
            { label: "Variant", value: data.variantAnalysisCostUsd, color: tokens.info },
            { label: "Dynamic", value: data.dynamicCostUsd, color: tokens.success },
            { label: "Patch", value: data.patchCostUsd, color: tokens.muted },
          ].filter((e) => e.value > 0),
        ).map((line, i) => (
          <Text key={`cost-${i}`}>  {line}</Text>
        ))}
        {data.budgetExceeded && (
          <>
            <Text>{""}</Text>
            <Text>
              {tokens.warnStrong("Budget exceeded:")} pipeline stopped early to stay within cost
              limit
            </Text>
          </>
        )}
        {data.auditLogDir && (
          <Text>
            {tokens.muted("Audit log:")} {data.auditLogDir}/
          </Text>
        )}

        {/* Run metrics */}
        {data.runMetrics && <RunMetricsSummary metrics={data.runMetrics} />}
      </Box>

      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}

function RunMetricsSummary({
  metrics,
}: {
  metrics: import("../../scoring/run-metrics.js").RunMetrics;
}): React.ReactElement {
  const verdictTotal = Object.values(metrics.verdictCounts).reduce((s, n) => s + n, 0);

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxDivider(terminalCardWidth(96, 60))}</Text>
      <Text>{tokens.label("Run Metrics")}</Text>
      <Text>{""}</Text>

      {verdictTotal > 0 && (
        <>
          {Object.entries(metrics.verdictCounts).map(([verdict, count]) => {
            const pct = ((count / verdictTotal) * 100).toFixed(1);
            return (
              <Text key={verdict}>
                {tokens.muted(`${verdict}:`)} {count} ({pct}%)
              </Text>
            );
          })}
          <Text>
            {tokens.muted("TP Rate:")} {(metrics.tpRate * 100).toFixed(1)}%
          </Text>
          <Text>
            {tokens.muted("FP Rate:")} {(metrics.fpRate * 100).toFixed(1)}%
          </Text>
          <Text>{""}</Text>
        </>
      )}

      {Object.keys(metrics.severityCounts).length > 0 && (
        <Text>
          {tokens.muted("Severity:")}{" "}
          {Object.entries(metrics.severityCounts)
            .map(([s, c]) => `${s}=${c}`)
            .join(", ")}
        </Text>
      )}
      {Object.keys(metrics.taskYield).length > 0 && (
        <Text>
          {tokens.muted("Task yield:")}{" "}
          {Object.entries(metrics.taskYield)
            .map(([s, c]) => `${s}=${c}`)
            .join(", ")}
        </Text>
      )}
      {metrics.averageConfidence > 0 && (
        <Text>
          {tokens.muted("Avg confidence:")} {(metrics.averageConfidence * 100).toFixed(1)}%
        </Text>
      )}
      {metrics.exploitabilityRate != null && (
        <Text>
          {tokens.muted("Exploitability rate:")} {(metrics.exploitabilityRate * 100).toFixed(1)}%
        </Text>
      )}
      <Text>
        {tokens.muted("Structured evidence:")} taint-path=
        {metrics.structuredEvidence.findingsWithTaintPath}
      </Text>

      <Text>{""}</Text>
      <Text>
        {tokens.muted("Duration:")} scan={formatDuration(metrics.durationBreakdown.scan)} triage=
        {formatDuration(metrics.durationBreakdown.triage)}
        {metrics.durationBreakdown.verify != null
          ? ` verify=${formatDuration(metrics.durationBreakdown.verify)}`
          : ""}
        {metrics.durationBreakdown.pocHarness != null
          ? ` poc=${formatDuration(metrics.durationBreakdown.pocHarness)}`
          : ""}{" "}
        total={formatDuration(metrics.durationBreakdown.total)}
      </Text>
      <Text>
        {tokens.muted("Cost:")} triage={formatCost(metrics.costBreakdown.triage)} verify=
        {formatCost(metrics.costBreakdown.verify)} poc=
        {formatCost(metrics.costBreakdown.pocHarness)} variant=
        {formatCost(metrics.costBreakdown.variantAnalysis)} total=
        {formatCost(metrics.costBreakdown.total)}
      </Text>
    </Box>
  );
}

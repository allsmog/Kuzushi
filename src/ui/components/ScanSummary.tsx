/**
 * Full scan summary display using box-drawing sections.
 */
import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import {
  colorVerdict,
  formatCost,
  formatDuration,
  miniBarChart,
  badge,
  boxHeader,
  boxFooter,
  boxDivider,
  treeLines,
} from "../format.js";
import { FindingCard } from "./FindingCard.js";
import type { SummaryData } from "../state.js";

interface ScanSummaryProps {
  data: SummaryData;
}

export function ScanSummary({ data }: ScanSummaryProps): React.ReactElement {
  const { verdictCounts: counts } = data;
  const total = counts.tp + counts.fp + counts.needs_review;

  const hasVerificationData = data.exploitable + data.notExploitable > 0
    || data.verifyErrors > 0
    || data.verificationCostUsd > 0;

  const hasPocData = data.pocGenerated > 0
    || data.pocSkipped > 0
    || data.pocHarnessErrors > 0
    || data.pocHarnessCostUsd > 0;

  const hasDynamic = data.dynamicConfirmed + data.dynamicInteresting + data.dynamicRejected + data.dynamicErrors > 0;

  const hasPatch = data.patchGenerated + data.patchVerified + data.patchFailed + data.patchErrors > 0;

  const hasIncremental = data.incrementalCachedFiles > 0 || data.incrementalRescannedFiles > 0;

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxHeader(`${icons.complete} Scan Results`, 60)}</Text>
      <Text>{""}</Text>

      {/* Failed tasks warning */}
      {data.failedTasks.length > 0 && (
        <Text>{"  "}{chalk.red("Scanners failed:")}  {data.failedTasks.join(", ")} {chalk.dim("(results may be incomplete)")}</Text>
      )}

      {/* Degradation warnings */}
      {data.extractionDegradation && data.extractionDegradation.status !== "ok" && (
        <Text>{"  "}{(data.extractionDegradation.status === "failed" ? chalk.red : chalk.yellow)("Extraction:")} {data.extractionDegradation.status} [{data.extractionDegradation.reasons.join(", ")}]</Text>
      )}
      {data.stitchDegradation && (
        <Text>{"  "}{chalk.yellow("Stitch:")} degraded [{data.stitchDegradation.reason}]</Text>
      )}
      {data.tiPriorDegraded && (
        <Text>{"  "}{chalk.yellow("TI Prior:")} degraded</Text>
      )}

      {/* Verdict counts */}
      <Text>{"  "}{chalk.dim("Total triaged:")}    {total}</Text>
      <Text>{"  "}{chalk.red.bold(`${icons.error} True positives:`)}   {counts.tp}</Text>
      <Text>{"  "}{chalk.green(`${icons.success} False positives:`)}  {counts.fp}</Text>
      <Text>{"  "}{chalk.yellow(`${icons.warning} Needs review:`)}     {counts.needs_review}</Text>

      {data.triageErrors > 0 && (
        <Text>{"  "}{chalk.red("Triage errors:")}     {data.triageErrors}</Text>
      )}
      {data.skippedLowConfidence > 0 && (
        <Text>{"  "}{chalk.dim("Skipped (low confidence):")} {data.skippedLowConfidence}</Text>
      )}
      {data.skippedByFpFilter > 0 && (
        <Text>{"  "}{chalk.dim("Skipped (hard exclusions):")} {data.skippedByFpFilter}</Text>
      )}
      {data.softSuppressedFindings > 0 && (
        <Text>{"  "}{chalk.dim("Soft-suppressed findings:")} {data.softSuppressedFindings}</Text>
      )}
      {data.skippedByLlmRescore > 0 && (
        <Text>{"  "}{chalk.dim("Skipped (LLM rescore):")} {data.skippedByLlmRescore}</Text>
      )}
      {data.corroboratedClusters > 0 && (
        <Text>{"  "}{chalk.dim("Corroborated clusters:")} {data.corroboratedClusters}</Text>
      )}
      {(data.verifyGateAutoAccepted > 0 || data.verifyGateSkipped > 0) && (
        <>
          <Text>{"  "}{chalk.dim("Gate auto-accepted:")}   {data.verifyGateAutoAccepted}</Text>
          <Text>{"  "}{chalk.dim("Gate skipped:")}          {data.verifyGateSkipped}</Text>
        </>
      )}

      {/* Verdict distribution bar */}
      {total > 0 && (
        <>
          <Text>{""}</Text>
          {miniBarChart([
            { label: "tp", value: counts.tp, color: chalk.red },
            { label: "fp", value: counts.fp, color: chalk.green },
            { label: "needs_review", value: counts.needs_review, color: chalk.yellow },
          ]).map((line, i) => (
            <Text key={i}>{"  "}{line}</Text>
          ))}
        </>
      )}

      {/* Verification section */}
      {hasVerificationData && (
        <>
          <Text>{""}</Text>
          <Text>{boxDivider(60)}</Text>
          <Text>{"  "}{chalk.bold("Verification")}</Text>
          <Text>{"  "}{chalk.red.bold(`${icons.error} Exploitable:`)}      {data.exploitable}</Text>
          <Text>{"  "}{chalk.green(`${icons.success} Not exploitable:`)}  {data.notExploitable}</Text>
          {data.verifyErrors > 0 && (
            <Text>{"  "}{chalk.red("Verification errors:")} {data.verifyErrors}</Text>
          )}
        </>
      )}

      {/* PoC section */}
      {hasPocData && (
        <>
          <Text>{""}</Text>
          <Text>{boxDivider(60)}</Text>
          <Text>{"  "}{chalk.bold("PoC Harnesses")}</Text>
          <Text>{"  "}{chalk.cyan(`${icons.gear} Generated:`)} {data.pocGenerated}</Text>
          <Text>{"  "}{chalk.yellow(`${icons.pending} Skipped:`)}   {data.pocSkipped}</Text>
          {data.pocHarnessErrors > 0 && (
            <Text>{"  "}{chalk.red("Errors:")}     {data.pocHarnessErrors}</Text>
          )}
          {data.pocOutputDir && (
            <Text>{"  "}{chalk.dim("Output dir:")} {data.pocOutputDir}</Text>
          )}
        </>
      )}

      {/* Variant findings */}
      {data.variantFindings > 0 && (
        <>
          <Text>{""}</Text>
          <Text>{"  "}{chalk.cyan("Variant findings:")}  {data.variantFindings}</Text>
        </>
      )}

      {/* Dynamic analysis */}
      {hasDynamic && (
        <>
          <Text>{""}</Text>
          <Text>{boxDivider(60)}</Text>
          <Text>{"  "}{chalk.bold("Dynamic Analysis")}</Text>
          <Text>{"    "}{chalk.red.bold(`Confirmed:`)}   {data.dynamicConfirmed}</Text>
          <Text>{"    "}{chalk.yellow(`Interesting:`)} {data.dynamicInteresting}</Text>
          <Text>{"    "}{chalk.green(`Rejected:`)}    {data.dynamicRejected}</Text>
          {data.dynamicErrors > 0 && (
            <Text>{"    "}{chalk.red("Errors:")}      {data.dynamicErrors}</Text>
          )}
          {data.dynamicCostUsd > 0 && (
            <Text>{"    "}{chalk.dim("Cost:")}        {formatCost(data.dynamicCostUsd)}</Text>
          )}
        </>
      )}

      {/* Incremental */}
      {hasIncremental && (
        <>
          <Text>{""}</Text>
          <Text>{"  "}{chalk.dim("Incremental:")} {chalk.green(`${data.incrementalCachedFiles} cached`)}, {data.incrementalRescannedFiles} rescanned{data.incrementalDepExpandedFiles > 0 ? `, ${data.incrementalDepExpandedFiles} dependency-expanded` : ""}</Text>
        </>
      )}

      {/* Patch synthesis */}
      {hasPatch && (
        <>
          <Text>{""}</Text>
          <Text>{boxDivider(60)}</Text>
          <Text>{"  "}{chalk.bold("Patch Synthesis")}</Text>
          <Text>{"    "}{chalk.cyan("Generated:")}  {data.patchGenerated}</Text>
          <Text>{"    "}{chalk.green("Verified:")}   {data.patchVerified} (finding eliminated after patch)</Text>
          {data.patchFailed > 0 && (
            <Text>{"    "}{chalk.red("Failed:")}     {data.patchFailed}</Text>
          )}
          {data.patchErrors > 0 && (
            <Text>{"    "}{chalk.red("Errors:")}     {data.patchErrors}</Text>
          )}
          {data.patchCostUsd > 0 && (
            <Text>{"    "}{chalk.dim("Cost:")}       {formatCost(data.patchCostUsd)}</Text>
          )}
        </>
      )}

      {/* Exploit chains */}
      {data.exploitChains.length > 0 && (
        <>
          <Text>{""}</Text>
          <Text>{boxDivider(60)}</Text>
          <Text>{"  "}{chalk.bold("Exploitation Chains")}</Text>
          <Text>{""}</Text>
          {data.exploitChains.map((chain, ci) => {
            const sevColor = chain.overallSeverity === "CRITICAL" ? chalk.red.bold
              : chain.overallSeverity === "HIGH" ? chalk.red : chalk.yellow;
            const stepTexts = chain.steps.map((step) =>
              `${chalk.dim(step.role + ":")} ${step.description} ${chalk.dim(`[${step.findingFingerprint.slice(0, 8)}]`)}`,
            );
            const treeSteps = treeLines(stepTexts, 4);
            return (
              <Box key={ci} flexDirection="column">
                <Text>{"  "}{sevColor(chain.overallSeverity)} {chalk.bold(chain.name)}</Text>
                {treeSteps.map((line, li) => <Text key={li}>{line}</Text>)}
                {chain.preconditions.length > 0 && (
                  <Text>{"    "}{chalk.dim("Preconditions:")} {chain.preconditions.join(", ")}</Text>
                )}
                <Text>{"    "}{chalk.dim("Impact:")} {chain.impactDescription}</Text>
                <Text>{""}</Text>
              </Box>
            );
          })}
        </>
      )}

      {/* Actionable findings */}
      {data.actionableFindings.length > 0 && (
        <>
          <Text>{""}</Text>
          <Text>{boxDivider(60)}</Text>
          <Text>{"  "}{chalk.bold("Actionable Findings")}</Text>
          <Text>{""}</Text>
          {data.actionableFindings.map((f, i) => (
            <FindingCard key={i} finding={f} />
          ))}
        </>
      )}
      {data.actionableFindings.length === 0 && total > 0 && (
        <>
          <Text>{""}</Text>
          <Text>{"  "}{chalk.green.bold(`${icons.success} All findings triaged as false positives. Code looks clean.`)}</Text>
        </>
      )}

      {/* Cost summary */}
      <Text>{""}</Text>
      <Text>{boxDivider(60)}</Text>
      <Text>{"  "}{chalk.dim("Triage cost:")} {formatCost(data.triageCostUsd)}</Text>
      {hasVerificationData && (
        <Text>{"  "}{chalk.dim("Verification cost:")} {formatCost(data.verificationCostUsd)}</Text>
      )}
      {hasPocData && (
        <Text>{"  "}{chalk.dim("PoC harness cost:")} {formatCost(data.pocHarnessCostUsd)}</Text>
      )}
      {data.variantAnalysisCostUsd > 0 && (
        <Text>{"  "}{chalk.dim("Variant analysis cost:")} {formatCost(data.variantAnalysisCostUsd)}</Text>
      )}
      {data.budgetExceeded && (
        <>
          <Text>{""}</Text>
          <Text>{"  "}{chalk.yellow.bold("Budget exceeded:")} pipeline stopped early to stay within cost limit</Text>
        </>
      )}
      {data.auditLogDir && (
        <Text>{"  "}{chalk.dim("Audit log:")} {data.auditLogDir}/</Text>
      )}

      {/* Run metrics */}
      {data.runMetrics && <RunMetricsSummary metrics={data.runMetrics} />}

      <Text>{boxFooter(60)}</Text>
    </Box>
  );
}

function RunMetricsSummary({ metrics }: { metrics: import("../../scoring/run-metrics.js").RunMetrics }): React.ReactElement {
  const verdictTotal = Object.values(metrics.verdictCounts).reduce((s, n) => s + n, 0);

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxDivider(60)}</Text>
      <Text>{"  "}{chalk.bold("Run Metrics")}</Text>
      <Text>{""}</Text>

      {verdictTotal > 0 && (
        <>
          {Object.entries(metrics.verdictCounts).map(([verdict, count]) => {
            const pct = ((count / verdictTotal) * 100).toFixed(1);
            return <Text key={verdict}>{"  "}{chalk.dim(`${verdict}:`)} {count} ({pct}%)</Text>;
          })}
          <Text>{"  "}{chalk.dim("TP Rate:")} {(metrics.tpRate * 100).toFixed(1)}%</Text>
          <Text>{"  "}{chalk.dim("FP Rate:")} {(metrics.fpRate * 100).toFixed(1)}%</Text>
          <Text>{""}</Text>
        </>
      )}

      {Object.keys(metrics.severityCounts).length > 0 && (
        <Text>{"  "}{chalk.dim("Severity:")} {Object.entries(metrics.severityCounts).map(([s, c]) => `${s}=${c}`).join(", ")}</Text>
      )}
      {Object.keys(metrics.taskYield).length > 0 && (
        <Text>{"  "}{chalk.dim("Task yield:")} {Object.entries(metrics.taskYield).map(([s, c]) => `${s}=${c}`).join(", ")}</Text>
      )}
      {metrics.averageConfidence > 0 && (
        <Text>{"  "}{chalk.dim("Avg confidence:")} {(metrics.averageConfidence * 100).toFixed(1)}%</Text>
      )}
      {metrics.exploitabilityRate != null && (
        <Text>{"  "}{chalk.dim("Exploitability rate:")} {(metrics.exploitabilityRate * 100).toFixed(1)}%</Text>
      )}
      <Text>{"  "}{chalk.dim("Structured evidence:")} taint-path={metrics.structuredEvidence.findingsWithTaintPath}</Text>

      <Text>{""}</Text>
      <Text>{"  "}{chalk.dim("Duration:")} scan={formatDuration(metrics.durationBreakdown.scan)} triage={formatDuration(metrics.durationBreakdown.triage)}{metrics.durationBreakdown.verify != null ? ` verify=${formatDuration(metrics.durationBreakdown.verify)}` : ""}{metrics.durationBreakdown.pocHarness != null ? ` poc=${formatDuration(metrics.durationBreakdown.pocHarness)}` : ""} total={formatDuration(metrics.durationBreakdown.total)}</Text>
      <Text>{"  "}{chalk.dim("Cost:")} triage={formatCost(metrics.costBreakdown.triage)} verify={formatCost(metrics.costBreakdown.verify)} poc={formatCost(metrics.costBreakdown.pocHarness)} variant={formatCost(metrics.costBreakdown.variantAnalysis)} total={formatCost(metrics.costBreakdown.total)}</Text>
    </Box>
  );
}

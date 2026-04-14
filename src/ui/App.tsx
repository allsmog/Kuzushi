/**
 * Main Ink application component.
 * Renders the full Kuzushi terminal UI based on UIStore state.
 */
import React from "react";
import { Box, Text, Static } from "ink";
import chalk from "chalk";
import { useUIState } from "./hooks.js";
import { icons } from "./icons.js";
import type { UIStore, ResultLine as ResultLineData } from "./state.js";
import { Banner } from "./components/Banner.js";
import { StageHeader } from "./components/StageHeader.js";
import { ProgressBar } from "./components/ProgressBar.js";
import { AgentActivity } from "./components/AgentActivity.js";
import { ResultLine } from "./components/ResultLine.js";
import { ScanSummary } from "./components/ScanSummary.js";
import { QualityGate } from "./components/QualityGate.js";
import { Spinner } from "./components/Spinner.js";

interface AppProps {
  store: UIStore;
}

export function App({ store }: AppProps): React.ReactElement {
  const state = useUIState(store);

  // Build a stage label based on current phase
  const stageLabel = buildStageLabel(state);

  // Separate completed results (rendered as static/permanent) from in-progress
  const completedResults = state.results;

  // Active agent activities
  const activeActivities = [...state.agentActivity.entries()];

  return (
    <Box flexDirection="column">
      {/* Banner — rendered once via Static */}
      {state.bannerShown && <Banner />}

      {/* Scan start info */}
      {state.startBannerShown && (
        <Static items={["start-banner"]}>
          {() => (
            <Box key="start-banner" flexDirection="column">
              <Text>{chalk.bold(`  ${icons.complete} Kuzushi — scanning ${state.repoName}`)}</Text>
              <Text>{"  "}{chalk.dim(icons.treeMiddle)} Scanners: {state.tasks.join(", ")}</Text>
              <Text>{"  "}{chalk.dim(icons.treeLast)} {state.totalFindings} findings, {state.selectedForTriage} selected for AI triage</Text>
              <Text>{""}</Text>
            </Box>
          )}
        </Static>
      )}

      {/* Skipped info */}
      {state.skippedAlreadyTriaged > 0 && state.phase === "triaging" && (
        <Static items={["skip-info"]}>
          {() => (
            <Text key="skip-info">{"  "}{chalk.dim(`Skipping ${state.skippedAlreadyTriaged} already-triaged findings, ${state.selectedForTriage} remaining`)}</Text>
          )}
        </Static>
      )}

      {/* Stage header */}
      {stageLabel && (state.phase === "scanning" || state.phase === "triaging" || state.phase === "verifying" || state.phase === "poc") && (
        <StageHeader phase={state.phase} label={stageLabel} />
      )}

      {/* Progress bar (during triage/verify/poc) */}
      {state.progress.total > 0 && (state.phase === "triaging" || state.phase === "verifying" || state.phase === "poc") && (
        <ProgressBar current={state.progress.current} total={state.progress.total} />
      )}

      {/* Completed results — rendered as static (scroll off) */}
      <Static items={completedResults.map((r, i) => ({ ...r, _key: `result-${i}` }))}>
        {(item) => <ResultLine key={item._key} data={item as ResultLineData} />}
      </Static>

      {/* Active agent activities — live, re-renders in place */}
      {activeActivities.map(([fp, lines]) => (
        <AgentActivity key={fp} fingerprint={fp} lines={lines} />
      ))}

      {/* Scanning spinner (when no progress yet) */}
      {state.phase === "scanning" && state.progress.total === 0 && (
        <Box>
          <Text>{"  "}</Text>
          <Spinner color="green" label="Running scanners..." />
        </Box>
      )}

      {/* Summary */}
      {state.phase === "summary" && state.summary && (
        <ScanSummary data={state.summary} />
      )}

      {/* Quality gate */}
      {state.qualityGate && (
        <QualityGate result={state.qualityGate} />
      )}
    </Box>
  );
}

function buildStageLabel(state: ReturnType<typeof useUIState>): string | null {
  switch (state.phase) {
    case "scanning":
      return `Scanning with ${state.tasks.join(", ")}...`;
    case "triaging":
      return `Triaging ${state.progress.total || state.selectedForTriage} findings via ${state.model}...`;
    case "verifying":
      return `Verifying ${state.progress.total} findings via ${state.model}...`;
    case "poc":
      return `Generating ${state.progress.total} PoC harnesses via ${state.model}...`;
    default:
      return null;
  }
}

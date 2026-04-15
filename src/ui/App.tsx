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
import { AgentActivity } from "./components/AgentActivity.js";
import { ResultLine } from "./components/ResultLine.js";
import { ScanSummary } from "./components/ScanSummary.js";
import { QualityGate } from "./components/QualityGate.js";
import { PipelineIndicator } from "./components/PipelineIndicator.js";

interface AppProps {
  store: UIStore;
}

export function App({ store }: AppProps): React.ReactElement {
  const state = useUIState(store);

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

      {/* Pipeline stage indicator — always visible during execution */}
      {state.stages.length > 0 && state.phase !== "summary" && state.phase !== "done" && (
        <PipelineIndicator stages={state.stages} progress={state.progress} />
      )}

      {/* Completed results — rendered as static (scroll off) */}
      <Static items={completedResults.map((r, i) => ({ ...r, _key: `result-${i}` }))}>
        {(item) => <ResultLine key={item._key} data={item as ResultLineData} />}
      </Static>

      {/* Active agent activities — live, re-renders in place */}
      {activeActivities.map(([fp, lines]) => (
        <AgentActivity key={fp} fingerprint={fp} lines={lines} />
      ))}

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


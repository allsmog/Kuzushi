/**
 * Main Ink application component.
 * Renders the full Kuzushi terminal UI based on UIStore state.
 *
 * Completed results go into <Static> (rendered once, never re-rendered).
 * Only the pipeline indicator + active finding stay in the live area
 * to minimize flicker from spinner ticks.
 */
import React from "react";
import { Box, Text, Static } from "ink";
import chalk from "chalk";
import { useUIState } from "./hooks.js";
import { icons } from "./icons.js";
import type { UIStore, ResultLine as ResultLineData } from "./state.js";
import { Banner } from "./components/Banner.js";
import { ResultLine } from "./components/ResultLine.js";
import { ScanSummary } from "./components/ScanSummary.js";
import { QualityGate } from "./components/QualityGate.js";
import { PipelineIndicator } from "./components/PipelineIndicator.js";
import { ConfigBanner } from "./components/ConfigBanner.js";
import { StatusFooter } from "./components/StatusFooter.js";

interface AppProps {
  store: UIStore;
}

export function App({ store }: AppProps): React.ReactElement {
  const state = useUIState(store);

  // Results that have scrolled past the live window go to Static (no re-render).
  // Only the last few stay in the live PipelineIndicator.
  const LIVE_RESULT_COUNT = 3;
  const staticResults = state.results.length > LIVE_RESULT_COUNT
    ? state.results.slice(0, -LIVE_RESULT_COUNT)
    : [];
  const liveResults = state.results.length > LIVE_RESULT_COUNT
    ? state.results.slice(-LIVE_RESULT_COUNT)
    : state.results;

  return (
    <Box flexDirection="column">
      {/* Banner — rendered once */}
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

      {/* Config banner — rendered once */}
      {state.configBanner && (
        <Static items={["config-banner"]}>
          {() => <ConfigBanner key="config-banner" config={state.configBanner!} />}
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

      {/* Completed results — rendered once via Static, never re-rendered */}
      <Static items={staticResults.map((r, i) => ({ ...r, _key: `r-${i}` }))}>
        {(item) => <ResultLine key={item._key} data={item as ResultLineData} />}
      </Static>

      {/* Pipeline indicator with live branches — the only re-rendering area */}
      {state.stages.length > 0 && state.phase !== "summary" && state.phase !== "done" && (
        <PipelineIndicator
          stages={state.stages}
          progress={state.progress}
          runningCostUsd={state.runningCostUsd}
          throttle={state.throttle}
          results={liveResults}
          agentActivity={state.agentActivity}
        />
      )}

      {/* Summary */}
      {state.phase === "summary" && state.summary && (
        <ScanSummary data={state.summary} />
      )}

      {/* Quality gate */}
      {state.qualityGate && (
        <QualityGate result={state.qualityGate} />
      )}

      {/* Persistent status footer */}
      {state.phase !== "idle" && state.phase !== "done" && state.phase !== "summary" && (
        <StatusFooter
          model={state.model || state.configBanner?.model || ""}
          phase={state.phase}
          runningCostUsd={state.runningCostUsd}
          progress={state.progress}
          startedAt={state.pipelineStartedAt}
          throttle={state.throttle}
        />
      )}
    </Box>
  );
}

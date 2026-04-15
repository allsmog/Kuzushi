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
import { ResumeDiff } from "./components/ResumeDiff.js";
import { CommandInput, type ReplCommand, type CommandResult } from "./components/CommandInput.js";
import { SetupWizard } from "./components/SetupWizard.js";
import { ConfigConfirm } from "./components/ConfigConfirm.js";
import { CredentialPrompt } from "./components/CredentialPrompt.js";
import { InteractiveReview } from "./components/InteractiveReview.js";
import { CompactHeader } from "./components/CompactHeader.js";
import { NoticeRail } from "./components/NoticeRail.js";
import { CopilotShell } from "./components/CopilotShell.js";
import { createReplContext, handleReplCommand } from "./repl.js";

interface AppProps {
  store: UIStore;
}

export function App({ store }: AppProps): React.ReactElement {
  const state = useUIState(store);
  const [replCtx] = React.useState(() => createReplContext(store));

  const handleCommand = React.useCallback((cmd: ReplCommand): CommandResult => {
    return handleReplCommand(replCtx, cmd);
  }, [replCtx]);

  // Results that have scrolled past the live window go to Static (no re-render).
  // Only the last few stay in the live PipelineIndicator.
  const LIVE_RESULT_COUNT = 3;
  const staticResults = state.results.length > LIVE_RESULT_COUNT
    ? state.results.slice(0, -LIVE_RESULT_COUNT)
    : [];
  const liveResults = state.results.length > LIVE_RESULT_COUNT
    ? state.results.slice(-LIVE_RESULT_COUNT)
    : state.results;
  const showCompactHeader = state.mode !== "preflight" && state.mode !== "shell" && state.repoName.length > 0;

  return (
    <Box flexDirection="column">
      <Banner />
      {showCompactHeader && (
        <CompactHeader
          repoName={state.repoName}
          tasks={state.tasks}
          totalFindings={state.startBannerShown ? state.totalFindings : undefined}
          selectedForTriage={state.startBannerShown ? state.selectedForTriage : undefined}
        />
      )}

      {/* Config banner — rendered once */}
      {state.configBanner && state.mode !== "preflight" && (
        <Static items={["config-banner"]}>
          {() => <ConfigBanner key="config-banner" config={state.configBanner!} />}
        </Static>
      )}

      {/* Resume diff — shown when resuming a previous run */}
      {state.resumeDiff && (
        <Static items={["resume-diff"]}>
          {() => <ResumeDiff key="resume-diff" data={state.resumeDiff!} />}
        </Static>
      )}

      {/* Skipped info (plain fallback if no resume diff) */}
      {!state.resumeDiff && state.skippedAlreadyTriaged > 0 && state.phase === "triaging" && state.mode === "running" && (
        <Static items={["skip-info"]}>
          {() => (
            <Text key="skip-info">{"  "}{chalk.dim(`Skipping ${state.skippedAlreadyTriaged} already-triaged findings, ${state.selectedForTriage} remaining`)}</Text>
          )}
        </Static>
      )}

      <NoticeRail notices={state.notices} />

      {state.mode === "preflight" && state.preflight?.kind === "wizard" && (
        <SetupWizard
          repoName={state.preflight.repoName}
          onComplete={state.preflight.onComplete}
          onCancel={state.preflight.onCancel}
        />
      )}
      {state.mode === "preflight" && state.preflight?.kind === "confirm" && (
        <ConfigConfirm
          config={state.preflight.config}
          repoName={state.preflight.repoName}
          onProceed={state.preflight.onProceed}
          onEdit={state.preflight.onEdit}
          onQuit={state.preflight.onQuit}
        />
      )}
      {state.mode === "preflight" && state.preflight?.kind === "credentials" && (
        <CredentialPrompt
          onComplete={state.preflight.onComplete}
          onCancel={state.preflight.onCancel}
        />
      )}

      {state.mode === "running" && (
        <>
          <Static items={staticResults.map((r, i) => ({ ...r, _key: `r-${i}` }))}>
            {(item) => <ResultLine key={item._key} data={item as ResultLineData} />}
          </Static>

          {state.stages.length > 0 && (
            <PipelineIndicator
              stages={state.stages}
              progress={state.progress}
              runningCostUsd={state.runningCostUsd}
              throttle={state.throttle}
              results={liveResults}
              agentActivity={state.agentActivity}
            />
          )}

          {state.qualityGate && (
            <QualityGate result={state.qualityGate} />
          )}

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

          <CommandInput
            active={state.phase === "triaging" || state.phase === "verifying" || state.phase === "scanning"}
            onCommand={handleCommand}
          />
        </>
      )}

      {state.mode === "summary" && state.summary && (
        <>
          <ScanSummary data={state.summary} />
          {state.qualityGate && <QualityGate result={state.qualityGate} />}
        </>
      )}

      {state.mode === "review" && state.review && (
        <InteractiveReview
          findings={state.review.findings}
          onVerdict={state.review.onVerdict}
          onQuit={state.review.onQuit}
        />
      )}

      {state.mode === "shell" && state.shell && (
        <CopilotShell store={store} />
      )}
    </Box>
  );
}

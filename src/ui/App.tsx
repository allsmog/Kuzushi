/**
 * Main Ink application component.
 * Renders the full Kuzushi terminal UI based on UIStore state.
 *
 * Completed results go into <Static> (rendered once, never re-rendered).
 * Only the pipeline indicator + active finding stay in the live area
 * to minimize flicker from spinner ticks.
 */

import { Box, Static, Text } from "ink";
import React from "react";
import { Banner } from "./components/Banner.js";
import { CommandInput, type CommandResult, type ReplCommand } from "./components/CommandInput.js";
import { CompactHeader } from "./components/CompactHeader.js";
import { ConfigBanner } from "./components/ConfigBanner.js";
import { ConfigConfirm } from "./components/ConfigConfirm.js";
import { ContextIntake } from "./components/ContextIntake.js";
import { CopilotShell } from "./components/CopilotShell.js";
import { CredentialPrompt } from "./components/CredentialPrompt.js";
import { InteractiveReview } from "./components/InteractiveReview.js";
import { NoticeRail } from "./components/NoticeRail.js";
import { PipelineIndicator } from "./components/PipelineIndicator.js";
import { QualityGate } from "./components/QualityGate.js";
import { ResultLine } from "./components/ResultLine.js";
import { ResumeDiff } from "./components/ResumeDiff.js";
import { ScanSummary } from "./components/ScanSummary.js";
import { SetupWizard } from "./components/SetupWizard.js";
import { StatusFooter } from "./components/StatusFooter.js";
import { ThreatModelEditor } from "./components/ThreatModelEditor.js";
import { KeybindingsProvider } from "./hooks/useKeybindings.js";
import { useUIState } from "./hooks.js";
import { Breadcrumb } from "./primitives/Breadcrumb.js";
import { KeybindFooter } from "./primitives/KeybindFooter.js";
import { createReplContext, handleReplCommand } from "./repl.js";
import type { ResultLine as ResultLineData, UIStore } from "./state.js";
import { tokens } from "./tokens.js";

interface AppProps {
  store: UIStore;
}

export function App({ store }: AppProps): React.ReactElement {
  return (
    <KeybindingsProvider>
      <AppInner store={store} />
    </KeybindingsProvider>
  );
}

function AppInner({ store }: AppProps): React.ReactElement {
  const state = useUIState(store);
  const [replCtx] = React.useState(() => createReplContext(store));

  const handleCommand = React.useCallback(
    (cmd: ReplCommand): CommandResult => {
      return handleReplCommand(replCtx, cmd);
    },
    [replCtx],
  );

  // Results that have scrolled past the live window go to Static (no re-render).
  // Only the last few stay in the live PipelineIndicator.
  const LIVE_RESULT_COUNT = 3;
  const staticResults =
    state.results.length > LIVE_RESULT_COUNT ? state.results.slice(0, -LIVE_RESULT_COUNT) : [];
  const liveResults =
    state.results.length > LIVE_RESULT_COUNT
      ? state.results.slice(-LIVE_RESULT_COUNT)
      : state.results;
  const showCompactHeader =
    state.mode !== "preflight" && state.mode !== "shell" && state.repoName.length > 0;

  // Shell mode renders only the CopilotShell — no scan banner/header/pipeline chrome
  if (state.mode === "shell") {
    return (
      <Box flexDirection="column">
        {state.shell && <CopilotShell store={store} />}
        <KeybindFooter />
      </Box>
    );
  }

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
      {state.breadcrumb && state.breadcrumb.segments.length > 0 ? (
        <Box paddingLeft={2} marginTop={1}>
          <Breadcrumb
            segments={state.breadcrumb.segments}
            currentStep={state.breadcrumb.currentStep}
            totalSteps={state.breadcrumb.totalSteps}
          />
        </Box>
      ) : null}

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
      {!state.resumeDiff &&
        state.skippedAlreadyTriaged > 0 &&
        state.phase === "triaging" &&
        state.mode === "running" && (
          <Static items={["skip-info"]}>
            {() => (
              <Text key="skip-info">
                {"  "}
                {tokens.muted(
                  `Skipping ${state.skippedAlreadyTriaged} already-triaged findings, ${state.selectedForTriage} remaining`,
                )}
              </Text>
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
      {state.mode === "preflight" && state.preflight?.kind === "context-intake" && (
        <ContextIntake
          initialContext={state.preflight.initialContext}
          onComplete={state.preflight.onComplete}
          onSkip={state.preflight.onSkip}
          onCancel={state.preflight.onCancel}
        />
      )}
      {state.mode === "preflight" && state.preflight?.kind === "threat-editor" && (
        <ThreatModelEditor
          threatModel={state.preflight.threatModel}
          onComplete={state.preflight.onComplete}
          onSkip={state.preflight.onSkip}
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

          {state.qualityGate && <QualityGate result={state.qualityGate} />}

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
            active={
              state.phase === "triaging" ||
              state.phase === "verifying" ||
              state.phase === "scanning"
            }
            onCommand={handleCommand}
          />
        </>
      )}

      {state.mode === "summary" && state.summary && (
        <Static items={["scan-summary"]}>
          {() => (
            <React.Fragment key="scan-summary">
              <ScanSummary data={state.summary!} />
              {state.qualityGate && <QualityGate result={state.qualityGate} />}
            </React.Fragment>
          )}
        </Static>
      )}

      {state.mode === "review" && state.review && (
        <InteractiveReview
          findings={state.review.findings}
          onVerdict={state.review.onVerdict}
          onQuit={state.review.onQuit}
        />
      )}

      <KeybindFooter />
    </Box>
  );
}

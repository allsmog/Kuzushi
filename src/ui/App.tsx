/**
 * Main Ink application component.
 * Renders the full Kuzushi terminal UI based on UIStore state.
 *
 * Completed results go into <Static> (rendered once, never re-rendered).
 * Only the pipeline indicator + active finding stay in the live area
 * to minimize flicker from spinner ticks.
 */

import { Box, Static, Text, useInput } from "ink";
import React from "react";
import { Banner } from "./components/Banner.js";
import type { CommandResult, ReplCommand } from "./components/CommandInput.js";
import { CompactHeader } from "./components/CompactHeader.js";
import { ConfigBanner } from "./components/ConfigBanner.js";
import { ConfigConfirm } from "./components/ConfigConfirm.js";
import { ConfigEditor } from "./components/ConfigEditor.js";
import { ContextIntake } from "./components/ContextIntake.js";
import { CopilotShell } from "./components/CopilotShell.js";
import { CredentialPrompt } from "./components/CredentialPrompt.js";
import { InteractiveReview } from "./components/InteractiveReview.js";
import { NoticeRail } from "./components/NoticeRail.js";
import { ResumeDiff } from "./components/ResumeDiff.js";
import { RunningView } from "./components/RunningView.js";
import { ScanSummary } from "./components/ScanSummary.js";
import { SetupWizard } from "./components/SetupWizard.js";
import { ThreatModelEditor } from "./components/ThreatModelEditor.js";
import { QualityGate } from "./components/QualityGate.js";
import { KeybindingsProvider } from "./hooks/useKeybindings.js";
import { shallowEqual, useUISelector } from "./hooks.js";
import { Breadcrumb } from "./primitives/Breadcrumb.js";
import { KeybindFooter } from "./primitives/KeybindFooter.js";
import { createReplContext, handleReplCommand } from "./repl.js";
import type { UIStore } from "./state.js";
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
  const [replCtx] = React.useState(() => createReplContext(store));

  const handleCommand = React.useCallback(
    (cmd: ReplCommand): CommandResult => {
      return handleReplCommand(replCtx, cmd);
    },
    [replCtx],
  );

  // Routing-only subscription — this hook re-renders only when one of these
  // fields changes (shallowEqual on the slice object). Spinner ticks, result
  // additions, progress updates, and agent-activity deltas happen on other
  // fields and do NOT re-render AppInner or the routing shell — they only
  // re-render the subtree that subscribes to them.
  const routing = useUISelector(
    store,
    (s) => ({
      mode: s.mode,
      phase: s.phase,
      preflight: s.preflight,
      configBanner: s.configBanner,
      resumeDiff: s.resumeDiff,
      skippedAlreadyTriaged: s.skippedAlreadyTriaged,
      selectedForTriage: s.selectedForTriage,
      notices: s.notices,
      breadcrumb: s.breadcrumb,
      repoName: s.repoName,
      tasks: s.tasks,
      totalFindings: s.totalFindings,
      startBannerShown: s.startBannerShown,
      costCapHalted: s.costCapHalted,
      heartbeatExpanded: s.heartbeatExpanded,
      noticeRailExpanded: s.noticeRailExpanded,
      summary: s.summary,
      qualityGate: s.qualityGate,
      review: s.review,
      shell: s.shell,
    }),
    shallowEqual,
  );

  // Key-handler state comes from a separate selector so key events that mutate
  // costCapHalted/heartbeatExpanded/noticeRailExpanded don't re-run effects
  // that depend on routing.
  const keyState = useUISelector(
    store,
    (s) => ({
      mode: s.mode,
      costCapHalted: s.costCapHalted,
      heartbeatExpanded: s.heartbeatExpanded,
      noticeRailExpanded: s.noticeRailExpanded,
      shellAbort: s.shell?.onAbort,
    }),
    shallowEqual,
  );

  useInput(
    (input, key) => {
      if (keyState.costCapHalted) {
        if (input === "c") {
          store.update({ costCapHalted: false });
          return;
        }
        if (input === "a" || (key.ctrl && input === "c")) {
          keyState.shellAbort?.();
          store.update({ costCapHalted: false });
          return;
        }
        return;
      }
      if (input === "1") store.update({ scanView: "pipeline" });
      else if (input === "2") store.update({ scanView: "findings" });
      else if (input === "3") store.update({ scanView: "cost" });
      else if (input === "m") store.update({ heartbeatExpanded: !keyState.heartbeatExpanded });
      else if (input === "n") store.update({ noticeRailExpanded: !keyState.noticeRailExpanded });
    },
    { isActive: keyState.mode === "running" && process.stdin.isTTY === true },
  );

  const showCompactHeader =
    routing.mode !== "preflight" && routing.mode !== "shell" && routing.repoName.length > 0;

  // Shell mode renders only the CopilotShell — no scan banner/header/pipeline chrome
  if (routing.mode === "shell") {
    return (
      <Box flexDirection="column">
        {routing.shell && <CopilotShell store={store} />}
        <KeybindFooter />
      </Box>
    );
  }

  return (
    <Box flexDirection="column">
      <Banner />
      {showCompactHeader && (
        <CompactHeader
          repoName={routing.repoName}
          tasks={routing.tasks}
          totalFindings={routing.startBannerShown ? routing.totalFindings : undefined}
          selectedForTriage={routing.startBannerShown ? routing.selectedForTriage : undefined}
        />
      )}
      {routing.breadcrumb && routing.breadcrumb.segments.length > 0 ? (
        <Box paddingLeft={2} marginTop={1}>
          <Breadcrumb
            segments={routing.breadcrumb.segments}
            currentStep={routing.breadcrumb.currentStep}
            totalSteps={routing.breadcrumb.totalSteps}
          />
        </Box>
      ) : null}

      {/* Config banner — rendered once */}
      {routing.configBanner && routing.mode !== "preflight" && (
        <Static items={["config-banner"]}>
          {() => <ConfigBanner key="config-banner" config={routing.configBanner!} />}
        </Static>
      )}

      {/* Resume diff — shown when resuming a previous run */}
      {routing.resumeDiff && (
        <Static items={["resume-diff"]}>
          {() => <ResumeDiff key="resume-diff" data={routing.resumeDiff!} />}
        </Static>
      )}

      {/* Skipped info (plain fallback if no resume diff) */}
      {!routing.resumeDiff &&
        routing.skippedAlreadyTriaged > 0 &&
        routing.phase === "triaging" &&
        routing.mode === "running" && (
          <Static items={["skip-info"]}>
            {() => (
              <Text key="skip-info">
                {"  "}
                {tokens.muted(
                  `Skipping ${routing.skippedAlreadyTriaged} already-triaged findings, ${routing.selectedForTriage} remaining`,
                )}
              </Text>
            )}
          </Static>
        )}

      <NoticeRail notices={routing.notices} expanded={routing.noticeRailExpanded} />

      {routing.mode === "preflight" && routing.preflight?.kind === "wizard" && (
        <SetupWizard
          repoName={routing.preflight.repoName}
          onComplete={routing.preflight.onComplete}
          onCancel={routing.preflight.onCancel}
        />
      )}
      {routing.mode === "preflight" && routing.preflight?.kind === "confirm" && (
        <ConfigConfirm
          config={routing.preflight.config}
          repoName={routing.preflight.repoName}
          onProceed={routing.preflight.onProceed}
          onEdit={routing.preflight.onEdit}
          onQuit={routing.preflight.onQuit}
        />
      )}
      {routing.mode === "preflight" && routing.preflight?.kind === "credentials" && (
        <CredentialPrompt
          onComplete={routing.preflight.onComplete}
          onCancel={routing.preflight.onCancel}
        />
      )}
      {routing.mode === "preflight" && routing.preflight?.kind === "context-intake" && (
        <ContextIntake
          initialContext={routing.preflight.initialContext}
          onComplete={routing.preflight.onComplete}
          onSkip={routing.preflight.onSkip}
          onCancel={routing.preflight.onCancel}
        />
      )}
      {routing.mode === "preflight" && routing.preflight?.kind === "threat-editor" && (
        <ThreatModelEditor
          threatModel={routing.preflight.threatModel}
          onComplete={routing.preflight.onComplete}
          onSkip={routing.preflight.onSkip}
          onCancel={routing.preflight.onCancel}
        />
      )}
      {routing.mode === "preflight" && routing.preflight?.kind === "config-editor" && (
        <ConfigEditor
          initialConfig={routing.preflight.initialConfig}
          configPath={routing.preflight.configPath}
          focusKey={routing.preflight.focusKey}
          onComplete={routing.preflight.onComplete}
          onCancel={routing.preflight.onCancel}
        />
      )}

      {routing.mode === "running" && (
        <RunningView store={store} onCommand={handleCommand} />
      )}

      {routing.mode === "summary" && routing.summary && (
        <Static items={["scan-summary"]}>
          {() => (
            <React.Fragment key="scan-summary">
              <ScanSummary data={routing.summary!} />
              {routing.qualityGate && <QualityGate result={routing.qualityGate} />}
            </React.Fragment>
          )}
        </Static>
      )}

      {routing.mode === "review" && routing.review && (
        <InteractiveReview
          findings={routing.review.findings}
          onVerdict={routing.review.onVerdict}
          onQuit={routing.review.onQuit}
        />
      )}

      <KeybindFooter />
    </Box>
  );
}

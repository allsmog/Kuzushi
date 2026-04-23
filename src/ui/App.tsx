/**
 * Main Ink application component.
 * Renders the full Kuzushi terminal UI based on UIStore state.
 *
 * Completed results go into <Static> (rendered once, never re-rendered).
 * Only the pipeline indicator + active finding stay in the live area
 * to minimize flicker from spinner ticks.
 */

import { Static, Text, useInput } from "ink";
import React from "react";
import { AppLayout } from "./components/AppLayout.js";
import { Banner } from "./components/Banner.js";
import type { CommandResult, ReplCommand } from "./components/CommandInput.js";
import { ConfigBanner } from "./components/ConfigBanner.js";
import { ConfigConfirm } from "./components/ConfigConfirm.js";
import { ConfigEditor } from "./components/ConfigEditor.js";
import { ContextIntake } from "./components/ContextIntake.js";
import { CopilotShell } from "./components/CopilotShell.js";
import { CredentialPrompt } from "./components/CredentialPrompt.js";
import { InteractiveReview } from "./components/InteractiveReview.js";
import { NoticeRail } from "./components/NoticeRail.js";
import { QualityGate } from "./components/QualityGate.js";
import { ResumeDiff } from "./components/ResumeDiff.js";
import { RunningView } from "./components/RunningView.js";
import { ScanSummary } from "./components/ScanSummary.js";
import { SetupWizard } from "./components/SetupWizard.js";
import { ThreatModelEditor } from "./components/ThreatModelEditor.js";
import { KeybindingsProvider } from "./hooks/useKeybindings.js";
import { useRawModeWatchdog } from "./hooks/useRawModeWatchdog.js";
import { shallowEqual, useUISelector } from "./hooks.js";
import { deriveNavigation, LayoutProvider, STANDARD_LAYOUT_THEME } from "./layout-context.js";
import { KeybindFooter } from "./primitives/KeybindFooter.js";
import { SpinnerClockProvider } from "./primitives/SpinnerClock.js";
import { createReplContext, handleReplCommand } from "./repl.js";
import type { UIStore } from "./state.js";
import { tokens } from "./tokens.js";

interface AppProps {
  store: UIStore;
}

export function App({ store }: AppProps): React.ReactElement {
  return (
    <KeybindingsProvider>
      <SpinnerClockProvider>
        <AppInner store={store} />
      </SpinnerClockProvider>
    </KeybindingsProvider>
  );
}

function AppInner({ store }: AppProps): React.ReactElement {
  // App-root raw-mode watchdog. Lives for the lifetime of AppInner so it
  // survives `mode` transitions ("shell" ↔ "running" ↔ "summary") that
  // unmount the per-mode subtrees. Without this, a Claude Agent SDK
  // subprocess spawned during `mode === "running"` could disable raw mode
  // and the only watchdog (in CopilotShell) would already be unmounted.
  useRawModeWatchdog();

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

  const layoutContext = React.useMemo(
    () => ({
      theme: STANDARD_LAYOUT_THEME,
      navigation: deriveNavigation({
        mode: routing.mode,
        phase: routing.phase,
        repoName: routing.repoName,
        shell: routing.shell,
      }),
    }),
    [routing.mode, routing.phase, routing.repoName, routing.shell],
  );

  return (
    <LayoutProvider value={layoutContext}>
      <AppLayout footer={<KeybindFooter />}>
        {routing.mode !== "shell" && <Banner />}
        {routing.mode === "shell" && routing.shell && <CopilotShell store={store} />}
        {/*
         * One-shot banners — config / resume / skip-info — share a single
         * <Static> region. Multiple Static regions in one Ink tree are
         * known to cause flicker (see CC's note in
         * cc-repo/src/utils/staticRender.tsx:8-10), so we batch them into
         * one items array. Each item carries the data needed to render
         * the right banner type.
         */}
        <PreflightBannersStatic
          configBanner={routing.mode !== "preflight" ? routing.configBanner : null}
          resumeDiff={routing.resumeDiff}
          skipInfo={
            !routing.resumeDiff &&
            routing.skippedAlreadyTriaged > 0 &&
            routing.phase === "triaging" &&
            routing.mode === "running"
              ? {
                  skipped: routing.skippedAlreadyTriaged,
                  remaining: routing.selectedForTriage,
                }
              : null
          }
        />

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

        {routing.mode === "running" && <RunningView store={store} onCommand={handleCommand} />}

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
      </AppLayout>
    </LayoutProvider>
  );
}

// ---------------------------------------------------------------------------
// Single-Static banner consolidation
// ---------------------------------------------------------------------------

type BannerItem =
  | { kind: "config"; data: NonNullable<ReturnType<typeof getConfigBannerType>> }
  | { kind: "resume"; data: NonNullable<ReturnType<typeof getResumeDiffType>> }
  | { kind: "skip"; skipped: number; remaining: number };

// Type-extracting helpers — purely for the BannerItem variants above.
function getConfigBannerType(): React.ComponentProps<typeof ConfigBanner>["config"] | null {
  return null;
}
function getResumeDiffType(): React.ComponentProps<typeof ResumeDiff>["data"] | null {
  return null;
}

interface PreflightBannersStaticProps {
  configBanner: React.ComponentProps<typeof ConfigBanner>["config"] | null | undefined;
  resumeDiff: React.ComponentProps<typeof ResumeDiff>["data"] | null | undefined;
  skipInfo: { skipped: number; remaining: number } | null;
}

const PreflightBannersStatic = React.memo(function PreflightBannersStatic({
  configBanner,
  resumeDiff,
  skipInfo,
}: PreflightBannersStaticProps): React.ReactElement | null {
  // Build the items array for <Static>. Items are stable as long as their
  // input is stable (parent passes already-narrow slices).
  const items = React.useMemo<Array<BannerItem & { _key: string }>>(() => {
    const out: Array<BannerItem & { _key: string }> = [];
    if (configBanner) out.push({ _key: "config", kind: "config", data: configBanner });
    if (resumeDiff) out.push({ _key: "resume", kind: "resume", data: resumeDiff });
    if (skipInfo)
      out.push({
        _key: "skip",
        kind: "skip",
        skipped: skipInfo.skipped,
        remaining: skipInfo.remaining,
      });
    return out;
  }, [configBanner, resumeDiff, skipInfo]);

  if (items.length === 0) return null;

  return (
    <Static items={items}>
      {(item) => {
        switch (item.kind) {
          case "config":
            return <ConfigBanner key={item._key} config={item.data} />;
          case "resume":
            return <ResumeDiff key={item._key} data={item.data} />;
          case "skip":
            return (
              <Text key={item._key}>
                {"  "}
                {tokens.muted(
                  `Skipping ${item.skipped} already-triaged findings, ${item.remaining} remaining`,
                )}
              </Text>
            );
        }
      }}
    </Static>
  );
});

/**
 * Running-mode subtree — renders the active scan UI.
 *
 * Subscribes only to slices it actually reads, via `useUISelector`. Keeps
 * App.tsx's top-level subscription narrow so store mutations in this
 * subtree (spinner ticks, progress updates, results) don't re-render the
 * routing shell.
 */

import { Box, Static, Text } from "ink";
import React from "react";
import { formatCost, formatDuration } from "../format.js";
import { useTerminalSize } from "../hooks/useTerminalSize.js";
import { shallowEqual, useElapsed, useUISelector } from "../hooks.js";
import { Ratchet } from "../primitives/Ratchet.js";
import type { ResultLine as ResultLineData, UIStore } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { HeartbeatStrip } from "./AgentActivity.js";
import type { CommandResult, ReplCommand } from "./CommandInput.js";
import { CommandInput } from "./CommandInput.js";
import { CostCapHalt } from "./CostCapHalt.js";
import { CostView } from "./CostView.js";
import { FindingsView } from "./FindingsView.js";
import { PipelineIndicator } from "./PipelineIndicator.js";
import { QualityGate } from "./QualityGate.js";
import { RateLimitBanner } from "./RateLimitBanner.js";
import { ResultLine } from "./ResultLine.js";
import { StatusFooter } from "./StatusFooter.js";

interface RunningViewProps {
  store: UIStore;
  onCommand: (cmd: ReplCommand) => CommandResult;
}

/** How many recent results stay in the live PipelineIndicator area vs Static. */
const LIVE_RESULT_COUNT = 3;

export const RunningView = React.memo(function RunningView({
  store,
  onCommand,
}: RunningViewProps): React.ReactElement {
  const scanView = useUISelector(store, (s) => s.scanView);
  const phase = useUISelector(store, (s) => s.phase);
  const results = useUISelector(store, (s) => s.results, shallowEqual);

  // Split results into Static (scrolled-past) vs live (kept in PipelineIndicator).
  // Memoize so array identity is stable when results array is stable.
  const { staticResults, liveResults } = React.useMemo(() => {
    if (results.length > LIVE_RESULT_COUNT) {
      return {
        staticResults: results.slice(0, -LIVE_RESULT_COUNT),
        liveResults: results.slice(-LIVE_RESULT_COUNT),
      };
    }
    return { staticResults: [] as typeof results, liveResults: results };
  }, [results]);

  const staticItems = React.useMemo(
    () => staticResults.map((r) => ({ ...r, _key: staticResultKey(r) })),
    [staticResults],
  );

  return (
    <Box
      flexDirection="column"
      flexGrow={1}
      height="100%"
      overflow="hidden"
      justifyContent="space-between"
    >
      <Box flexDirection="column" flexGrow={1} flexShrink={1} overflow="hidden">
        <Static items={staticItems}>
          {(item) => <ResultLine key={item._key} data={item as ResultLineData} />}
        </Static>

        <RunSummaryHeader store={store} scanView={scanView} />

        {scanView === "pipeline" && <PipelineTab store={store} liveResults={liveResults} />}
        {scanView === "findings" && <FindingsTab store={store} />}
        {scanView === "cost" && <CostTab store={store} />}

        <QualityGateSlot store={store} />
      </Box>

      <Box flexShrink={0}>
        <RunningBottomDock store={store} phase={phase} onCommand={onCommand} />
      </Box>
    </Box>
  );
});

function RunSummaryHeader({
  store,
  scanView,
}: {
  store: UIStore;
  scanView: "pipeline" | "findings" | "cost";
}): React.ReactElement {
  const state = useUISelector(
    store,
    (s) => ({
      repoName: s.repoName,
      phase: s.phase,
      tasks: s.tasks,
      stages: s.stages,
      totalFindings: s.totalFindings,
      runningCostUsd: s.runningCostUsd,
      pipelineStartedAt: s.pipelineStartedAt,
    }),
    shallowEqual,
  );
  const elapsedMs = useElapsed(state.pipelineStartedAt, 1000);
  const activeStage = state.stages.find((stage) => stage.status === "active");
  const activeTask = activeStage?.subTasks.find((task) => task.status === "active");
  const label = state.repoName || "scan";
  const work = activeTask?.label ?? activeStage?.detail ?? activeStage?.label ?? state.phase;
  const elapsed = state.pipelineStartedAt ? formatDuration(elapsedMs) : "0s";
  const taskCount = state.tasks.length;
  const findings = `${state.totalFindings} finding${state.totalFindings === 1 ? "" : "s"}`;
  const viewLabel =
    scanView === "pipeline" ? "pipeline" : scanView === "findings" ? "findings" : "cost";

  return (
    <Box marginBottom={SPACING.sm}>
      <Text>
        {tokens.accent("●")} {tokens.label(label)}
        {tokens.muted(" · ")}
        {tokens.value(work)}
        {tokens.muted(" · ")}
        {tokens.muted(`${taskCount} task${taskCount === 1 ? "" : "s"}`)}
        {tokens.muted(" · ")}
        {tokens.muted(elapsed)}
        {tokens.muted(" · ")}
        {tokens.value(findings)}
        {tokens.muted(" · ")}
        {tokens.value(formatCost(state.runningCostUsd))}
        {tokens.muted(" · view ")}
        {tokens.value(viewLabel)}
      </Text>
    </Box>
  );
}

function RunningBottomDock({
  store,
  phase,
  onCommand,
}: {
  store: UIStore;
  phase: string;
  onCommand: (cmd: ReplCommand) => CommandResult;
}): React.ReactElement {
  const showStatusFooter = phase !== "idle" && phase !== "done" && phase !== "summary";
  return (
    <Box flexDirection="column">
      <StableDockSlot minHeight={3}>
        <AdvisoryStack store={store} />
      </StableDockSlot>
      <StableDockSlot minHeight={1}>
        <HeartbeatSlot store={store} />
      </StableDockSlot>
      <StableDockSlot minHeight={showStatusFooter ? 3 : 0}>
        {showStatusFooter ? <StatusFooterSlot store={store} /> : null}
      </StableDockSlot>
      <StableDockSlot minHeight={1}>
        <CommandInputSlot store={store} phase={phase} onCommand={onCommand} />
      </StableDockSlot>
    </Box>
  );
}

function StableDockSlot({
  children,
  minHeight = 0,
}: {
  children: React.ReactNode;
  minHeight?: number;
}): React.ReactElement {
  return (
    <Ratchet>
      <Box flexDirection="column" minHeight={minHeight || undefined}>
        {children}
      </Box>
    </Ratchet>
  );
}

function AdvisoryStack({ store }: { store: UIStore }): React.ReactElement {
  return (
    <Box flexDirection="column">
      <RateLimitSlot store={store} />
      <CostCapHaltSlot store={store} />
    </Box>
  );
}

// --- Tab containers: each subscribes to exactly what it renders ------------

function PipelineTab({
  store,
  liveResults,
}: {
  store: UIStore;
  liveResults: ResultLineData[];
}): React.ReactElement | null {
  const stages = useUISelector(store, (s) => s.stages, shallowEqual);
  const progress = useUISelector(store, (s) => s.progress, shallowEqual);
  const runningCostUsd = useUISelector(store, (s) => s.runningCostUsd);
  const throttle = useUISelector(store, (s) => s.throttle, shallowEqual);
  const etaMs = useUISelector(store, (s) => s.etaMs);
  const agentActivity = useUISelector(store, (s) => s.agentActivity);
  const { rows } = useTerminalSize();
  const rowBudget = Math.max(6, rows - 12);

  if (stages.length === 0) return null;
  return (
    <PipelineIndicator
      stages={stages}
      progress={progress}
      runningCostUsd={runningCostUsd}
      throttle={throttle}
      results={liveResults}
      agentActivity={agentActivity}
      etaMs={etaMs}
      rowBudget={rowBudget}
    />
  );
}

function FindingsTab({ store }: { store: UIStore }): React.ReactElement {
  const results = useUISelector(store, (s) => s.results, shallowEqual);
  return <FindingsView results={results} />;
}

function CostTab({ store }: { store: UIStore }): React.ReactElement {
  const results = useUISelector(store, (s) => s.results, shallowEqual);
  const runningCostUsd = useUISelector(store, (s) => s.runningCostUsd);
  const budget = useUISelector(store, (s) => s.configBanner?.budget);
  return <CostView results={results} runningCostUsd={runningCostUsd} budget={budget} />;
}

function QualityGateSlot({ store }: { store: UIStore }): React.ReactElement | null {
  const qualityGate = useUISelector(store, (s) => s.qualityGate);
  return qualityGate ? <QualityGate result={qualityGate} /> : null;
}

function RateLimitSlot({ store }: { store: UIStore }): React.ReactElement {
  const throttle = useUISelector(store, (s) => s.throttle, shallowEqual);
  return <RateLimitBanner throttle={throttle} />;
}

function CostCapHaltSlot({ store }: { store: UIStore }): React.ReactElement | null {
  const costCapHalted = useUISelector(store, (s) => s.costCapHalted);
  const runningCostUsd = useUISelector(store, (s) => s.runningCostUsd);
  const budgetUsd = useUISelector(store, (s) => s.costCapBudgetUsd ?? s.configBanner?.budget);
  if (!costCapHalted) return null;
  return <CostCapHalt runningCostUsd={runningCostUsd} budgetUsd={budgetUsd} />;
}

function HeartbeatSlot({ store }: { store: UIStore }): React.ReactElement {
  // HeartbeatStrip reads many fields internally; pass the narrow state slice.
  // Subscribing to the whole UIState object here is fine because HeartbeatStrip
  // is a terminal consumer — it re-renders anyway on activity updates.
  // `phase` is included so the strip can switch its agents-active count
  // from triage/verify fingerprints to active scan sub-tasks while
  // `phase === "scanning"`.
  const state = useUISelector(
    store,
    (s) => ({
      mode: s.mode,
      phase: s.phase,
      agentActivity: s.agentActivity,
      pipelineStartedAt: s.pipelineStartedAt,
      runningCostUsd: s.runningCostUsd,
      stages: s.stages,
      throttle: s.throttle,
      heartbeatExpanded: s.heartbeatExpanded,
    }),
    shallowEqual,
  );
  // The component expects the full UIState but only reads these fields.
  // Cast is safe — HeartbeatStrip pulls only what's listed above.
  return (
    <HeartbeatStrip
      state={state as unknown as import("../state.js").UIState}
      expanded={state.heartbeatExpanded}
    />
  );
}

function StatusFooterSlot({ store }: { store: UIStore }): React.ReactElement {
  const model = useUISelector(store, (s) => s.model || s.configBanner?.model || "");
  const phase = useUISelector(store, (s) => s.phase);
  const runningCostUsd = useUISelector(store, (s) => s.runningCostUsd);
  const progress = useUISelector(store, (s) => s.progress, shallowEqual);
  const pipelineStartedAt = useUISelector(store, (s) => s.pipelineStartedAt);
  const throttle = useUISelector(store, (s) => s.throttle, shallowEqual);
  const costCapUsd = useUISelector(store, (s) => s.costCapBudgetUsd);
  return (
    <StatusFooter
      model={model}
      phase={phase}
      runningCostUsd={runningCostUsd}
      progress={progress}
      startedAt={pipelineStartedAt}
      throttle={throttle}
      {...(costCapUsd != null ? { costCapUsd } : {})}
    />
  );
}

function CommandInputSlot({
  store,
  phase,
  onCommand,
}: {
  store: UIStore;
  phase: string;
  onCommand: (cmd: ReplCommand) => CommandResult;
}): React.ReactElement {
  const active = phase === "triaging" || phase === "verifying" || phase === "scanning";
  return <CommandInput active={active} onCommand={onCommand} />;
}

function staticResultKey(result: ResultLineData): string {
  return `${result.kind}:${result.fingerprint}:${result.index}:${result.total}`;
}

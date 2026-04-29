/**
 * Carlini threat-hunt module home — Readiness / Scope / Actions.
 *
 * Reads from the shared threat-model + context snapshots so the page can
 * render before any hunt has run. `actorsFromDocument` partitions actors
 * into "ready" (≥1 HIGH/CRITICAL threat) vs "deferred" (no high-severity
 * threats yet).
 */

import type React from "react";
import type { ThreatModelDocument } from "../../../agents/tasks/threat-modeling/types.js";
import { actorsFromDocument } from "../../../modules/carlini-threat-hunt/selectors.js";
import { loadContextSnapshot } from "../../../modules/sast/context-persist.js";
import { readThreatModelKbStatus } from "../../../modules/threat-model/kb-index.js";
import { loadOperatorScanContext } from "../../../operator-context.js";
import { loadPersistentThreatModel } from "../../../threat-model-renderer.js";
import { useRegisterKeybindings } from "../../hooks/useKeybindings.js";
import type { ContextSnapshot, ShellState } from "../../state.js";
import { RuleHeader } from "../RuleHeader.js";
import { ScreenContent } from "../ScreenContent.js";
import { AttachmentsBlock } from "./AttachmentsBlock.js";
import { KeyValueSection } from "./context-home.js";
import type { ModuleHomeProps } from "./types.js";

const MODULE_ID = "carlini-threat-hunt";

interface Row {
  key: string;
  value: string;
}

function formatActors(doc: ThreatModelDocument | null | undefined): string {
  const { prioritized, allActors } = actorsFromDocument(doc);
  if (allActors.length === 0) return "(no actors yet) — build threat model first";
  const ready = prioritized.length;
  const deferred = allActors.length - ready;
  return `${ready} ready · ${deferred} deferred`;
}

function activeTarget(shell: ShellState): string | null {
  return shell.target ?? shell.contextSnapshot?.target ?? null;
}

function resolveContextSnapshot(shell: ShellState): ContextSnapshot | null {
  const target = activeTarget(shell);
  if (shell.contextSnapshot && (!target || shell.contextSnapshot.target === target)) {
    return shell.contextSnapshot;
  }
  if (!target) return null;
  return loadContextSnapshot(target);
}

function resolveThreatModel(shell: ShellState): ThreatModelDocument | null {
  const target = activeTarget(shell);
  if (target) {
    const persisted = loadPersistentThreatModel(target);
    if (persisted) return persisted;
  }
  return shell.threatModel ?? null;
}

function formatSnapshot(snapshot: ContextSnapshot | null): string {
  if (!snapshot) return "missing — /use context; run .";
  const generated = snapshot.generatedSlices?.length
    ? ` · ${snapshot.generatedSlices.join(", ")}`
    : "";
  return `.kuzushi/context-snapshot.json · target ${snapshot.target}${generated}`;
}

function operatorContextLabel(shell: ShellState): string {
  const target = activeTarget(shell);
  if (!target) return "(no target)";
  const scanContext = loadOperatorScanContext(target);
  if (!scanContext) return "missing — /context build";
  const countItems = (value: unknown): number => (Array.isArray(value) ? value.length : 0);
  const count =
    countItems(scanContext.trust?.deploymentModel) +
    countItems(scanContext.trust?.infrastructure) +
    countItems(scanContext.trust?.externalDefenses) +
    countItems(scanContext.trust?.confirmedMitigations) +
    countItems(scanContext.scope?.highValuePaths) +
    countItems(scanContext.scope?.lowValuePaths) +
    countItems(scanContext.scope?.sensitiveDataTags) +
    countItems(scanContext.architecture?.entryPoints) +
    countItems(scanContext.architecture?.externalDeps) +
    countItems(scanContext.architecture?.dataFlows) +
    countItems(scanContext.historical?.suppressedFpFingerprints) +
    countItems(scanContext.historical?.confirmedTpFingerprints);
  const review = scanContext.operatorReviewed ? "reviewed" : "unreviewed";
  return count > 0
    ? `.kuzushi/scan-context.json · ${count} hint${count === 1 ? "" : "s"} · ${review}`
    : ".kuzushi/scan-context.json · empty · review with /context edit";
}

function threatModelLabel(threatModel: ThreatModelDocument | null): string {
  if (!threatModel) return "missing — /use threat-model; run .";
  const threats = threatModel.threats.length;
  return `.kuzushi/threat-model.json · ${threats} threat${threats === 1 ? "" : "s"}`;
}

function readinessRows(shell: ShellState): Row[] {
  const snapshot = resolveContextSnapshot(shell);
  const threatModel = resolveThreatModel(shell);
  const dfd = threatModel?.dfd;
  const nodeCount = dfd?.nodes?.length ?? 0;
  const flowCount = dfd?.flows?.length ?? 0;
  const boundaryCount = dfd?.trustBoundaries?.length ?? 0;
  const actorIds = new Set(
    (dfd?.nodes ?? []).filter((node) => node.type === "external-entity").map((node) => node.id),
  );
  const actorLinkedThreats =
    threatModel?.threats.filter((threat) =>
      (threat.actorIds ?? []).some((actorId) => actorIds.has(actorId)),
    ).length ?? 0;
  const fallback =
    threatModel?.provenance?.fallback ||
    threatModel?.threats.some((threat) => threat.provenance?.fallback)
      ? "fallback"
      : "generated";
  const kbStatus = threatKbStatus(shell);
  return [
    { key: "app context", value: formatSnapshot(snapshot) },
    { key: "operator context", value: operatorContextLabel(shell) },
    { key: "threat model", value: threatModelLabel(threatModel) },
    {
      key: "attack surface",
      value:
        nodeCount === 0 && flowCount === 0
          ? "missing DFD — /use threat-model; run ."
          : `${nodeCount} nodes · ${flowCount} flows · ${boundaryCount} boundaries`,
    },
    { key: "s4 quality", value: `${actorLinkedThreats} actor-linked threats · ${fallback}` },
    { key: "threat KB", value: kbStatus },
    { key: "actors", value: formatActors(threatModel) },
  ];
}

function threatKbStatus(shell: ShellState): string {
  const target = activeTarget(shell);
  if (!target) return "(no target)";
  const status = readThreatModelKbStatus(target, shell.threatModel);
  if (!status.exists) return ".kuzushi/threat-model-kb.sqlite3 · missing";
  const chunks = status.stats ? `${status.stats.chunks} chunks` : "unknown chunks";
  return status.current
    ? `.kuzushi/threat-model-kb.sqlite3 · current · ${chunks}`
    : `.kuzushi/threat-model-kb.sqlite3 · stale (${status.staleReason ?? "unknown"}) · ${chunks}`;
}

function scopeRows(shell: ShellState): Row[] {
  const tune = shell.tuneSnapshot;
  const tools = shell.moduleOptions?.[`${MODULE_ID}:run`] ?? {};
  const model = (tools["model"] as string | undefined) ?? tune?.model ?? "(default)";
  const effort = (tools["effort"] as string | undefined) ?? "xhigh";
  return [
    { key: "target", value: shell.target ?? "(none)" },
    { key: "mode", value: tune?.preset ?? "(default)" },
    { key: "model", value: model },
    { key: "effort", value: effort },
    { key: "evidence", value: ".kuzushi/findings.sqlite3" },
    { key: "kb", value: ".kuzushi/threat-model-kb.sqlite3" },
    { key: "output", value: "scrollback · /findings · /open <F-NNNN>" },
  ];
}

function actionRows(shell: ShellState): Row[] {
  const card = shell.moduleCatalog?.find((c) => c.id === MODULE_ID);
  const rows: Row[] = [
    { key: "/use context; run .", value: "build app context snapshot" },
    { key: "/context build", value: "build operator scan context notes" },
    { key: "/use threat-model; run .", value: "write .kuzushi/threat-model.json" },
    { key: "run .", value: "spawn one agent per ready actor" },
    { key: "run --changed", value: "scope to git-changed files only" },
    { key: "prompts", value: "edit the actor system prompt" },
    { key: "/threats dfd", value: "review the attack surface" },
  ];
  if (card?.runState?.kind === "resume") {
    rows.unshift({ key: "resume", value: card.runState.summary });
  } else if (card?.runState?.kind === "complete") {
    rows.unshift({ key: `replay ${card.runState.runId}`, value: card.runState.summary });
  }
  return rows;
}

export function CarliniThreatHuntHome({ shell }: ModuleHomeProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "Enter", label: "type tool verb" },
    { keys: "a", label: "attachments", secondary: true },
    { keys: "t", label: "tune", secondary: true },
    { keys: "f", label: "findings", secondary: true },
    { keys: "b", label: "back", secondary: true },
    { keys: "?", label: "help", secondary: true },
  ]);
  const slice = shell.kbState?.[MODULE_ID] ?? null;
  return (
    <ScreenContent>
      <RuleHeader breadcrumb={`kuzushi/${MODULE_ID}`} />
      <KeyValueSection title="readiness" rows={readinessRows(shell)} />
      <KeyValueSection title="scope" rows={scopeRows(shell)} />
      <AttachmentsBlock slice={slice} moduleId={MODULE_ID} />
      <KeyValueSection title="actions" rows={actionRows(shell)} />
    </ScreenContent>
  );
}

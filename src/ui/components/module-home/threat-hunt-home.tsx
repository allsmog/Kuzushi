/**
 * Threat-hunt module home — Readiness / Scope / Actions.
 *
 * Reads from the shared threat-model + context snapshots so the page can
 * render before any hunt has run. `actorsFromDocument` partitions actors
 * into "ready" (≥1 HIGH/CRITICAL threat) vs "deferred" (no high-severity
 * threats yet).
 */

import type React from "react";
import type { ThreatModelDocument } from "../../../agents/tasks/threat-modeling/types.js";
import { actorsFromDocument } from "../../../modules/threat-hunt/selectors.js";
import { useRegisterKeybindings } from "../../hooks/useKeybindings.js";
import type { ShellState } from "../../state.js";
import { RuleHeader } from "../RuleHeader.js";
import { ScreenContent } from "../ScreenContent.js";
import { KeyValueSection } from "./context-home.js";
import type { ModuleHomeProps } from "./types.js";

const MODULE_ID = "threat-hunt";

interface Row {
  key: string;
  value: string;
}

function formatActors(doc: ThreatModelDocument | null | undefined): string {
  const { prioritized, allActors } = actorsFromDocument(doc);
  if (allActors.length === 0) return "(no actors yet) — run context first";
  const ready = prioritized.length;
  const deferred = allActors.length - ready;
  return `${ready} ready · ${deferred} deferred`;
}

function readinessRows(shell: ShellState): Row[] {
  const snapshot = shell.contextSnapshot ?? null;
  const dfd = shell.threatModel?.dfd;
  const nodeCount = dfd?.elements?.length ?? 0;
  const boundaryCount = dfd?.trustBoundaries?.length ?? 0;
  const flowEdges = dfd?.elements?.filter((el) => el.type === "data-flow").length ?? 0;
  const snapshotLabel = snapshot
    ? `target ${snapshot.target}`
    : "(no snapshot — run /context build)";
  return [
    { key: "context", value: snapshotLabel },
    {
      key: "attack surface",
      value:
        nodeCount === 0 && flowEdges === 0
          ? "(no DFD)"
          : `${nodeCount} nodes · ${flowEdges} flows · ${boundaryCount} boundaries`,
    },
    { key: "actors", value: formatActors(shell.threatModel) },
  ];
}

function scopeRows(shell: ShellState): Row[] {
  const tune = shell.tuneSnapshot;
  const tools = shell.moduleOptions?.[`${MODULE_ID}:run`] ?? {};
  const model = (tools["model"] as string | undefined) ?? tune?.model ?? "(default)";
  const effort = (tools["effort"] as string | undefined) ?? "max";
  return [
    { key: "target", value: shell.target ?? "(none)" },
    { key: "mode", value: tune?.preset ?? "(default)" },
    { key: "model", value: model },
    { key: "effort", value: effort },
    { key: "evidence", value: ".kuzushi/findings.sqlite3" },
    { key: "output", value: "scrollback · /findings · /open <F-NNNN>" },
  ];
}

function actionRows(): Row[] {
  return [
    { key: "run .", value: "spawn one agent per ready actor" },
    { key: "run --changed", value: "scope to git-changed files only" },
    { key: "prompts", value: "edit the actor system prompt" },
    { key: "/threats dfd", value: "review the attack surface" },
  ];
}

export function ThreatHuntHome({ shell }: ModuleHomeProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "Enter", label: "type tool verb" },
    { keys: "t", label: "tune", secondary: true },
    { keys: "f", label: "findings", secondary: true },
    { keys: "b", label: "back", secondary: true },
    { keys: "?", label: "help", secondary: true },
  ]);
  return (
    <ScreenContent>
      <RuleHeader breadcrumb={`kuzushi/${MODULE_ID}`} />
      <KeyValueSection title="readiness" rows={readinessRows(shell)} />
      <KeyValueSection title="scope" rows={scopeRows(shell)} />
      <KeyValueSection title="actions" rows={actionRows()} />
    </ScreenContent>
  );
}

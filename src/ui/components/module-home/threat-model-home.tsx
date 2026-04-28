/**
 * Threat-model module home — Status / Actions / Attachments / Last run.
 */

import type React from "react";
import { useRegisterKeybindings } from "../../hooks/useKeybindings.js";
import type { ShellState } from "../../state.js";
import { RuleHeader } from "../RuleHeader.js";
import { ScreenContent } from "../ScreenContent.js";
import { AttachmentsBlock } from "./AttachmentsBlock.js";
import { KeyValueSection } from "./context-home.js";
import type { ModuleHomeProps } from "./types.js";

const MODULE_ID = "threat-model";

interface Row {
  key: string;
  value: string;
}

function statusRows(shell: ShellState): Row[] {
  const tune = shell.tuneSnapshot;
  const card = shell.moduleCatalog?.find((c) => c.id === MODULE_ID);
  const lastRun = card?.lastRunSummary ?? "never run for this workspace";
  const tools = shell.moduleOptions?.[`${MODULE_ID}:build`] ?? {};
  const methodology = (tools["methodology"] as string | undefined) ?? "pasta (default)";
  const model = (tools["model"] as string | undefined) ?? tune?.model ?? "(default)";
  return [
    { key: "repo", value: shell.target ?? "(no target set)" },
    { key: "methodology", value: methodology },
    { key: "model", value: model },
    { key: "last run", value: lastRun },
  ];
}

function actionRows(): Row[] {
  return [
    { key: "attach <path>", value: "stage RFCs, diagrams, runbooks, audit reports as evidence" },
    { key: "/kb", value: "browse staged attachments (cursor + preview)" },
    { key: "run .", value: "build the threat model (PASTA S1-S4)" },
    { key: "/threats dfd", value: "open the attack-surface workspace" },
    { key: "methodologies", value: "list selectable methodologies" },
  ];
}

export function ThreatModelHome({ shell }: ModuleHomeProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "Enter", label: "type tool verb" },
    { keys: "a", label: "attachments", secondary: true },
    { keys: "t", label: "tune", secondary: true },
    { keys: "b", label: "back", secondary: true },
    { keys: "?", label: "help", secondary: true },
  ]);
  const slice = shell.kbState?.[MODULE_ID] ?? null;
  return (
    <ScreenContent>
      <RuleHeader breadcrumb={`kuzushi/${MODULE_ID}`} />
      <KeyValueSection title="status" rows={statusRows(shell)} />
      <AttachmentsBlock slice={slice} moduleId={MODULE_ID} />
      <KeyValueSection title="actions" rows={actionRows()} />
    </ScreenContent>
  );
}

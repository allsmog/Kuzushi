/**
 * Operator context intake — multi-section progressive editor.
 *
 * Auto-populated from task outputs, operators review each item and accept,
 * edit, delete, or skip. Navigation uses the shared useBoundedIndex hook,
 * inline edit mode uses the shared <TextInput> primitive, and keybindings
 * flow through useRegisterKeybindings so the footer reflects context.
 */

import { Box, Text, useInput } from "ink";
import type React from "react";
import { useCallback, useState } from "react";
import type { IntakeItemStatus, OperatorContextItem, OperatorScanContext } from "../../types.js";
import { boxFooter, boxHeader, terminalCardWidth } from "../format.js";
import { useBoundedIndex } from "../hooks/useBoundedIndex.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { icons } from "../icons.js";
import { TextInput } from "../primitives/TextInput.js";
import { tokens } from "../tokens.js";

type IntakeSection = "trust" | "scope" | "architecture" | "historical";
const SECTIONS: IntakeSection[] = ["trust", "scope", "architecture", "historical"];
const SECTION_LABELS: Record<IntakeSection, string> = {
  trust: "Trust Context",
  scope: "Scope Prioritization",
  architecture: "Architecture",
  historical: "Historical Feedback",
};

interface ContextIntakeProps {
  initialContext: OperatorScanContext;
  onComplete: (context: OperatorScanContext) => void;
  onSkip: () => void;
  onCancel: () => void;
}

interface DisplayItem {
  label: string;
  groupLabel?: string;
  status: IntakeItemStatus;
  path: [string, string, number];
}

function statusIcon(status: IntakeItemStatus): string {
  switch (status) {
    case "accepted":
      return tokens.success(icons.success);
    case "edited":
      return tokens.warn("\u270E");
    case "deleted":
      return tokens.danger(icons.error);
    case "added":
      return tokens.accent("+");
    default:
      return tokens.muted(icons.pending);
  }
}

function getDisplayItems(ctx: OperatorScanContext, section: IntakeSection): DisplayItem[] {
  const items: DisplayItem[] = [];

  if (section === "trust") {
    for (const [i, v] of ctx.trust.deploymentModel.entries()) {
      items.push({
        label: v.value,
        groupLabel: i === 0 ? "Deployment" : undefined,
        status: v.status,
        path: ["trust", "deploymentModel", i],
      });
    }
    for (const [i, v] of ctx.trust.infrastructure.entries()) {
      items.push({
        label: v.value,
        groupLabel: i === 0 ? "Infrastructure" : undefined,
        status: v.status,
        path: ["trust", "infrastructure", i],
      });
    }
    for (const [i, v] of ctx.trust.externalDefenses.entries()) {
      items.push({
        label: v.value,
        groupLabel: i === 0 ? "External Defenses" : undefined,
        status: v.status,
        path: ["trust", "externalDefenses", i],
      });
    }
    for (const [i, v] of ctx.trust.confirmedMitigations.entries()) {
      items.push({
        label: v.value,
        groupLabel: i === 0 ? "Confirmed Mitigations" : undefined,
        status: v.status,
        path: ["trust", "confirmedMitigations", i],
      });
    }
  } else if (section === "scope") {
    for (const [i, v] of ctx.scope.highValuePaths.entries()) {
      items.push({
        label: v.value,
        groupLabel: i === 0 ? "High-Value Paths" : undefined,
        status: v.status,
        path: ["scope", "highValuePaths", i],
      });
    }
    for (const [i, v] of ctx.scope.lowValuePaths.entries()) {
      items.push({
        label: v.value,
        groupLabel: i === 0 ? "Low-Value Paths" : undefined,
        status: v.status,
        path: ["scope", "lowValuePaths", i],
      });
    }
    for (const [i, v] of ctx.scope.sensitiveDataTags.entries()) {
      const locs = v.value.locations.join(", ");
      items.push({
        label: `${v.value.sensitivity}/${v.value.dataType}: ${locs}`,
        groupLabel: i === 0 ? "Sensitive Data" : undefined,
        status: v.status,
        path: ["scope", "sensitiveDataTags", i],
      });
    }
  } else if (section === "architecture") {
    for (const [i, v] of ctx.architecture.entryPoints.entries()) {
      const desc = v.value.method ? `${v.value.method} ${v.value.path}` : v.value.path;
      items.push({
        label: `${desc} (${v.value.kind})`,
        groupLabel: i === 0 ? "Entry Points" : undefined,
        status: v.status,
        path: ["architecture", "entryPoints", i],
      });
    }
    for (const [i, v] of ctx.architecture.externalDeps.entries()) {
      items.push({
        label: `${v.value.name} [${v.value.trustLevel}]`,
        groupLabel: i === 0 ? "External Dependencies" : undefined,
        status: v.status,
        path: ["architecture", "externalDeps", i],
      });
    }
    for (const [i, v] of ctx.architecture.dataFlows.entries()) {
      const cls = v.value.dataClassification ? ` [${v.value.dataClassification}]` : "";
      items.push({
        label: `${v.value.from} ${icons.arrow} ${v.value.to}${cls}`,
        groupLabel: i === 0 ? "Data Flows" : undefined,
        status: v.status,
        path: ["architecture", "dataFlows", i],
      });
    }
  } else if (section === "historical") {
    for (const [i, v] of ctx.historical.suppressedFpFingerprints.entries()) {
      const reason = v.value.reason ? ` (${v.value.reason})` : "";
      items.push({
        label: `FP: ${v.value.ruleId}${reason}`,
        groupLabel: i === 0 ? "Suppressed False Positives" : undefined,
        status: v.status,
        path: ["historical", "suppressedFpFingerprints", i],
      });
    }
    for (const [i, v] of ctx.historical.confirmedTpFingerprints.entries()) {
      items.push({
        label: `TP: ${v.value.ruleId}`,
        groupLabel: i === 0 ? "Confirmed True Positives" : undefined,
        status: v.status,
        path: ["historical", "confirmedTpFingerprints", i],
      });
    }
  }

  return items;
}

function mutateItemStatus(
  ctx: OperatorScanContext,
  path: [string, string, number],
  status: IntakeItemStatus,
): OperatorScanContext {
  const [sectionKey, arrayName, index] = path;
  const section = {
    ...(ctx as unknown as Record<string, Record<string, OperatorContextItem<unknown>[]>>)[
      sectionKey
    ]!,
  };
  const arr = [...section[arrayName]!];
  arr[index] = { ...arr[index]!, status };
  section[arrayName] = arr;
  return { ...ctx, [sectionKey]: section };
}

function acceptAllInSection(ctx: OperatorScanContext, section: IntakeSection): OperatorScanContext {
  const items = getDisplayItems(ctx, section);
  let updated = ctx;
  for (const item of items) {
    if (item.status === "skipped") {
      updated = mutateItemStatus(updated, item.path, "accepted");
    }
  }
  return updated;
}

const EDIT_KEYBINDS = [
  { keys: "Enter", label: "Save" },
  { keys: "Esc", label: "Cancel" },
];

const NAV_KEYBINDS = [
  { keys: "\u2191/\u2193", label: "Navigate" },
  { keys: "a", label: "Accept" },
  { keys: "e", label: "Edit" },
  { keys: "d", label: "Delete" },
  { keys: "A", label: "Accept all", secondary: true },
  { keys: "Tab", label: "Next section", secondary: true },
];

export function ContextIntake({
  initialContext,
  onComplete,
  onSkip,
  onCancel,
}: ContextIntakeProps): React.ReactElement {
  const [sectionIdx, setSectionIdx] = useState(0);
  const [context, setContext] = useState<OperatorScanContext>({ ...initialContext });
  const [editMode, setEditMode] = useState(false);
  const [editBuffer, setEditBuffer] = useState("");
  const width = terminalCardWidth();

  const currentSection = SECTIONS[sectionIdx]!;
  const displayItems = getDisplayItems(context, currentSection);

  const nav = useBoundedIndex(displayItems.length, {
    isActive: !editMode,
    wrap: false,
  });
  const selectedIdx = nav.index;

  useRegisterKeybindings(editMode ? EDIT_KEYBINDS : NAV_KEYBINDS);

  const advanceSection = useCallback(() => {
    if (sectionIdx >= SECTIONS.length - 1) {
      const finalCtx: OperatorScanContext = {
        ...context,
        operatorReviewed: true,
        lastReviewedAt: new Date().toISOString(),
      };
      onComplete(finalCtx);
    } else {
      setSectionIdx((i) => i + 1);
      nav.setIndex(0);
    }
  }, [sectionIdx, context, onComplete, nav]);

  // Command keys (not handled by useBoundedIndex or TextInput)
  useInput(
    (input, key) => {
      if (editMode) return;
      if (key.tab) {
        advanceSection();
      } else if (key.escape || input === "q") {
        onCancel();
      } else if (input === "a" && !key.shift) {
        const item = displayItems[selectedIdx];
        if (item) setContext(mutateItemStatus(context, item.path, "accepted"));
      } else if (input === "A") {
        setContext(acceptAllInSection(context, currentSection));
        advanceSection();
      } else if (input === "d") {
        const item = displayItems[selectedIdx];
        if (item) setContext(mutateItemStatus(context, item.path, "deleted"));
      } else if (input === "s") {
        const item = displayItems[selectedIdx];
        if (item) setContext(mutateItemStatus(context, item.path, "skipped"));
      } else if (input === "e") {
        const item = displayItems[selectedIdx];
        if (item && typeof item.label === "string") {
          const [sectionKey, arrayName, index] = item.path;
          const section = (
            context as unknown as Record<string, Record<string, OperatorContextItem<unknown>[]>>
          )[sectionKey];
          const raw = section?.[arrayName]?.[index];
          setEditBuffer(typeof raw?.value === "string" ? raw.value : item.label);
          setEditMode(true);
        }
      } else if (input === "S") {
        onSkip();
      } else if (key.return) {
        advanceSection();
      }
    },
    { isActive: !editMode },
  );

  const commitEdit = (value: string) => {
    const trimmed = value.trim();
    if (trimmed) {
      const item = displayItems[selectedIdx];
      if (item) {
        const [sectionKey, arrayName, index] = item.path;
        const section = {
          ...(
            context as unknown as Record<string, Record<string, OperatorContextItem<unknown>[]>>
          )[sectionKey]!,
        };
        const arr = [...section[arrayName]!];
        const current = arr[index]!;
        if (typeof current.value === "string") {
          arr[index] = {
            ...current,
            value: trimmed,
            status: "edited",
            original: current.original ?? current.value,
          };
          section[arrayName] = arr;
          setContext({ ...context, [sectionKey]: section });
        }
      }
    }
    setEditMode(false);
    setEditBuffer("");
  };

  const cancelEdit = () => {
    setEditMode(false);
    setEditBuffer("");
  };

  if (displayItems.length === 0) {
    return (
      <Box flexDirection="column">
        <Text>{""}</Text>
        <Text>
          {boxHeader(
            `Scan Context: ${SECTION_LABELS[currentSection]} (${sectionIdx + 1}/${SECTIONS.length})`,
            width,
          )}
        </Text>
        <Text>{""}</Text>
        <Box paddingLeft={2}>
          <Text>{tokens.muted("No items detected for this section.")}</Text>
        </Box>
        <Box paddingLeft={2}>
          <Text>{tokens.muted("Press [tab] or [enter] to continue, [n] to add items.")}</Text>
        </Box>
        <Text>{""}</Text>
        <Text>{boxFooter(width)}</Text>
      </Box>
    );
  }

  let lastGroup: string | undefined;

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>
        {boxHeader(
          `Scan Context: ${SECTION_LABELS[currentSection]} (${sectionIdx + 1}/${SECTIONS.length})`,
          width,
        )}
      </Text>
      <Text>{""}</Text>

      {displayItems.map((item, i) => {
        const showGroup = item.groupLabel && item.groupLabel !== lastGroup;
        if (item.groupLabel) lastGroup = item.groupLabel;
        const isSelected = i === selectedIdx;
        const cursor = isSelected ? tokens.accent("> ") : "  ";
        const icon = statusIcon(item.status);
        const label =
          item.status === "deleted"
            ? tokens.subtle(item.label)
            : isSelected
              ? tokens.strong(item.label)
              : tokens.muted(item.label);

        return (
          <Box key={i} flexDirection="column">
            {showGroup && (
              <Box paddingLeft={2}>
                <Text>{tokens.heading(item.groupLabel!)}</Text>
              </Box>
            )}
            <Text>
              {cursor}
              {icon} {label}
            </Text>
          </Box>
        );
      })}

      {editMode && (
        <Box marginTop={1} paddingLeft={2}>
          <Text>{tokens.accent("Edit: ")}</Text>
          <TextInput
            value={editBuffer}
            onChange={setEditBuffer}
            onSubmit={commitEdit}
            onCancel={cancelEdit}
            prefix=""
          />
        </Box>
      )}

      {(() => {
        const accepted = displayItems.filter(
          (i) => i.status === "accepted" || i.status === "edited",
        ).length;
        const deleted = displayItems.filter((i) => i.status === "deleted").length;
        const pending = displayItems.filter((i) => i.status === "skipped").length;
        return (
          <Box marginTop={1} paddingLeft={2}>
            <Text>
              {tokens.muted("Items:")}
              {accepted > 0 ? ` ${tokens.success(`${accepted} accepted`)}` : ""}
              {deleted > 0 ? ` ${tokens.danger(`${deleted} deleted`)}` : ""}
              {pending > 0 ? ` ${tokens.muted(`${pending} pending`)}` : ""}
            </Text>
          </Box>
        );
      })()}

      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}

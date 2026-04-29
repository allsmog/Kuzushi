/**
 * Interactive threat model editor — review, dismiss, mitigate, annotate.
 *
 * Uses useBoundedIndex for navigation and TextInput for annotations so the
 * component shares keyboard code with the rest of the interactive fleet.
 * Keybindings publish through useRegisterKeybindings for the shared footer.
 */

import { Box, Text, useInput } from "ink";
import type React from "react";
import { useState } from "react";
import type {
  StrideThreat,
  ThreatModelDocument,
} from "../../agents/tasks/threat-modeling/types.js";
import { badge } from "../format.js";
import { useBoundedIndex } from "../hooks/useBoundedIndex.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { icons } from "../icons.js";
import { isCancelInput } from "../interaction-key-policy.js";
import { TextInput } from "../primitives/TextInput.js";
import { dangerStrong, info, muted, SPACING, tokens, warnStrong } from "../tokens.js";

interface ThreatModelEditorProps {
  threatModel: ThreatModelDocument;
  onComplete: (updated: ThreatModelDocument) => void;
  onSkip: () => void;
  onCancel: () => void;
}

type ThreatStatus = "active" | "dismissed" | "mitigated";

function getThreatStatus(threat: StrideThreat, doc: ThreatModelDocument): ThreatStatus {
  if (doc.dismissedThreats?.includes(threat.id)) return "dismissed";
  if (
    doc.confirmedMitigations?.some(
      (m) =>
        threat.existingMitigations.some((em) => em.toLowerCase().includes(m.toLowerCase())) ||
        threat.missingMitigations.length === 0,
    )
  )
    return "mitigated";
  return "active";
}

function impactBadge(impact: string): string {
  switch (impact) {
    case "critical":
      return badge(impact, "red");
    case "high":
      return dangerStrong(impact.toUpperCase());
    case "medium":
      return warnStrong(impact.toUpperCase());
    case "low":
      return info(impact.toUpperCase());
    default:
      return muted(impact);
  }
}

function statusBadge(status: ThreatStatus): string {
  switch (status) {
    case "dismissed":
      return badge("DISMISSED", "magenta");
    case "mitigated":
      return badge("MITIGATED", "green");
    default:
      return "";
  }
}

function categoryLabel(cat: string): string {
  return tokens.muted(`[${cat}]`);
}

const NAV_KEYBINDS = [
  { keys: "\u2191/\u2193", label: "Navigate" },
  { keys: "m", label: "Mitigate" },
  { keys: "d", label: "Dismiss" },
  { keys: "r", label: "Restore", secondary: true },
  { keys: "a", label: "Annotate", secondary: true },
  { keys: "q", label: "Done" },
];

const ANNOTATE_KEYBINDS = [
  { keys: "Enter", label: "Save" },
  { keys: "Esc", label: "Cancel" },
];

export function ThreatModelEditor({
  threatModel,
  onComplete,
  onSkip,
  onCancel: _onCancel,
}: ThreatModelEditorProps): React.ReactElement {
  const [model, setModel] = useState<ThreatModelDocument>({ ...threatModel });
  const [annotateMode, setAnnotateMode] = useState(false);
  const [annotateBuffer, setAnnotateBuffer] = useState("");

  const threats = model.threats;

  const nav = useBoundedIndex(threats.length, {
    wrap: false,
    isActive: !annotateMode,
  });
  const selectedIdx = nav.index;
  const threat = threats[selectedIdx];

  useRegisterKeybindings(annotateMode ? ANNOTATE_KEYBINDS : NAV_KEYBINDS);

  const VISIBLE_COUNT = 8;
  const scrollStart = Math.max(
    0,
    Math.min(selectedIdx - Math.floor(VISIBLE_COUNT / 2), threats.length - VISIBLE_COUNT),
  );
  const visibleThreats = threats.slice(scrollStart, scrollStart + VISIBLE_COUNT);

  const finish = () => {
    const updated: ThreatModelDocument = {
      ...model,
      userEdited: true,
      lastEditedAt: new Date().toISOString(),
    };
    onComplete(updated);
  };

  useInput(
    (input, key) => {
      if (annotateMode) return;
      if (input === "d" && threat) {
        const dismissed = [...(model.dismissedThreats ?? [])];
        if (!dismissed.includes(threat.id)) dismissed.push(threat.id);
        setModel({ ...model, dismissedThreats: dismissed });
      } else if (input === "m" && threat) {
        const confirmed = [...(model.confirmedMitigations ?? [])];
        const mitigation = `${threat.title} (operator-confirmed)`;
        if (!confirmed.includes(mitigation)) confirmed.push(mitigation);
        const dismissed = (model.dismissedThreats ?? []).filter((id) => id !== threat.id);
        setModel({ ...model, confirmedMitigations: confirmed, dismissedThreats: dismissed });
      } else if (input === "r" && threat) {
        const dismissed = (model.dismissedThreats ?? []).filter((id) => id !== threat.id);
        const confirmed = (model.confirmedMitigations ?? []).filter(
          (m) => !m.includes(threat.title),
        );
        setModel({ ...model, dismissedThreats: dismissed, confirmedMitigations: confirmed });
      } else if (input === "a" && threat) {
        setAnnotateBuffer(model.userAnnotations?.[threat.id] ?? "");
        setAnnotateMode(true);
      } else if (input === "q" || isCancelInput(input, key)) {
        finish();
      } else if (input === "S") {
        onSkip();
      }
    },
    { isActive: !annotateMode },
  );

  const commitAnnotation = (value: string) => {
    if (threat && value.trim()) {
      const annotations = { ...(model.userAnnotations ?? {}) };
      annotations[threat.id] = value.trim();
      setModel({ ...model, userAnnotations: annotations });
    }
    setAnnotateMode(false);
    setAnnotateBuffer("");
  };

  const cancelAnnotation = () => {
    setAnnotateMode(false);
    setAnnotateBuffer("");
  };

  if (threats.length === 0) {
    return (
      <Box flexDirection="column">
        <Box paddingLeft={SPACING.md}>
          <Text>{tokens.label("Threat Model Editor")}</Text>
          <Text>{tokens.muted("No threats in threat model.")}</Text>
        </Box>
      </Box>
    );
  }

  const activeCount = threats.filter((t) => getThreatStatus(t, model) === "active").length;
  const dismissedCount = threats.filter((t) => getThreatStatus(t, model) === "dismissed").length;
  const mitigatedCount = threats.filter((t) => getThreatStatus(t, model) === "mitigated").length;

  return (
    <Box flexDirection="column">
      <Box paddingLeft={SPACING.md}>
        <Text>{tokens.label(`Threat Model Editor (${threats.length} threats)`)}</Text>
        <Text>
          {tokens.success(`${activeCount} active`)} {tokens.muted(`${dismissedCount} dismissed`)}{" "}
          {tokens.info(`${mitigatedCount} mitigated`)}
        </Text>
        <Text>
          {tokens.hint(`(${selectedIdx + 1} of ${threats.length})`)}
          {selectedIdx > 0 ? tokens.hint(" ▲") : ""}
          {selectedIdx < threats.length - 1 ? tokens.hint(" ▼") : ""}
        </Text>
      </Box>
      <Text>{""}</Text>

      {visibleThreats.map((t, vi) => {
        const realIdx = scrollStart + vi;
        const isSelected = realIdx === selectedIdx;
        const status = getThreatStatus(t, model);
        const cursor = isSelected ? tokens.focus("❯ ") : "  ";
        const annotation = model.userAnnotations?.[t.id];
        const statusCell = statusBadge(status);

        const titleText =
          status === "dismissed"
            ? tokens.subtle(t.title)
            : isSelected
              ? tokens.strong(t.title)
              : t.title;

        return (
          <Box key={t.id} flexDirection="column">
            <Text>
              {isSelected
                ? tokens.selection(`${cursor}${tokens.muted(t.id)} ${titleText} ${statusCell}`)
                : `${cursor}${tokens.muted(t.id)} ${titleText} ${statusCell}`}
            </Text>
            <Box paddingLeft={SPACING.xxl}>
              <Text>
                {icons.bullet} {impactBadge(t.impact)} {tokens.muted("likelihood:")} {t.likelihood}{" "}
                {categoryLabel(t.category)}
              </Text>
            </Box>
            {isSelected && (
              <Box flexDirection="column" paddingLeft={SPACING.xxl}>
                {t.attackVector && (
                  <Text>
                    {tokens.muted("Attack:")} {t.attackVector.slice(0, 70)}
                    {t.attackVector.length > 70 ? "..." : ""}
                  </Text>
                )}
                {t.existingMitigations.length > 0 && (
                  <Text>
                    {tokens.success("Mitigations:")} {t.existingMitigations.join(", ")}
                  </Text>
                )}
                {t.missingMitigations.length > 0 && (
                  <Text>
                    {tokens.warn("Missing:")} {t.missingMitigations.join(", ")}
                  </Text>
                )}
                {annotation && (
                  <Text>
                    {tokens.accent("Note:")} {annotation}
                  </Text>
                )}
              </Box>
            )}
            {vi < visibleThreats.length - 1 && <Text>{""}</Text>}
          </Box>
        );
      })}

      {threats.length > VISIBLE_COUNT && (
        <Box paddingLeft={SPACING.md}>
          <Text>
            {tokens.muted(
              `Showing ${scrollStart + 1}-${Math.min(scrollStart + VISIBLE_COUNT, threats.length)} of ${threats.length}`,
            )}
          </Text>
        </Box>
      )}

      {annotateMode && (
        <Box marginTop={SPACING.sm} paddingLeft={SPACING.md}>
          <Text>{tokens.accent("Note: ")}</Text>
          <TextInput
            value={annotateBuffer}
            onChange={setAnnotateBuffer}
            onSubmit={commitAnnotation}
            onCancel={cancelAnnotation}
            prefix=""
          />
        </Box>
      )}
    </Box>
  );
}

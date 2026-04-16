/**
 * Interactive threat model editor — review, dismiss, annotate threats.
 *
 *   ┌─ Threat Model Editor (12 threats) ──────────────────┐
 *   │                                                      │
 *   │  > T-01  SQL Injection via user search               │
 *   │         ● HIGH  likelihood: high  [elevation-of-priv]│
 *   │         Mitigations: parameterized queries           │
 *   │                                                      │
 *   │    T-02  XSS in admin panel           [DISMISSED]    │
 *   │         ● MEDIUM  likelihood: medium  [tampering]    │
 *   │                                                      │
 *   │  [↑↓] navigate  [m] mitigate  [d] dismiss           │
 *   │  [r] restore  [a] annotate  [q] done                 │
 *   └────────────────────────────────────────────────────┘
 */
import React, { useState } from "react";
import { Box, Text, useInput } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import { boxHeader, boxFooter, terminalCardWidth } from "../format.js";
import type {
  ThreatModelDocument,
  StrideThreat,
} from "../../agents/tasks/threat-modeling/types.js";

interface ThreatModelEditorProps {
  threatModel: ThreatModelDocument;
  onComplete: (updated: ThreatModelDocument) => void;
  onSkip: () => void;
  onCancel: () => void;
}

type ThreatStatus = "active" | "dismissed" | "mitigated";

function getThreatStatus(threat: StrideThreat, doc: ThreatModelDocument): ThreatStatus {
  if (doc.dismissedThreats?.includes(threat.id)) return "dismissed";
  if (doc.confirmedMitigations?.some((m) =>
    threat.existingMitigations.some((em) => em.toLowerCase().includes(m.toLowerCase()))
    || threat.missingMitigations.length === 0
  )) return "mitigated";
  return "active";
}

function impactBadge(impact: string): string {
  switch (impact) {
    case "critical": return chalk.bgRed.white.bold(` ${impact.toUpperCase()} `);
    case "high": return chalk.red.bold(impact.toUpperCase());
    case "medium": return chalk.yellow(impact.toUpperCase());
    case "low": return chalk.dim(impact.toUpperCase());
    default: return chalk.dim(impact);
  }
}

function statusBadge(status: ThreatStatus): string {
  switch (status) {
    case "dismissed": return chalk.bgGray.white(" DISMISSED ");
    case "mitigated": return chalk.bgGreen.white(" MITIGATED ");
    case "active":
    default: return "";
  }
}

function categoryLabel(cat: string): string {
  return chalk.dim(`[${cat}]`);
}

export function ThreatModelEditor({
  threatModel,
  onComplete,
  onSkip,
  onCancel,
}: ThreatModelEditorProps): React.ReactElement {
  const [model, setModel] = useState<ThreatModelDocument>({ ...threatModel });
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [annotateMode, setAnnotateMode] = useState(false);
  const [annotateBuffer, setAnnotateBuffer] = useState("");
  const width = terminalCardWidth();

  const threats = model.threats;
  const threat = threats[selectedIdx];

  // Scroll window
  const VISIBLE_COUNT = 8;
  const scrollStart = Math.max(0, Math.min(selectedIdx - Math.floor(VISIBLE_COUNT / 2), threats.length - VISIBLE_COUNT));
  const visibleThreats = threats.slice(scrollStart, scrollStart + VISIBLE_COUNT);

  const finish = () => {
    const updated: ThreatModelDocument = {
      ...model,
      userEdited: true,
      lastEditedAt: new Date().toISOString(),
    };
    onComplete(updated);
  };

  useInput((input, key) => {
    if (annotateMode) {
      if (key.return) {
        if (threat && annotateBuffer.trim()) {
          const annotations = { ...(model.userAnnotations ?? {}) };
          annotations[threat.id] = annotateBuffer.trim();
          setModel({ ...model, userAnnotations: annotations });
        }
        setAnnotateMode(false);
        setAnnotateBuffer("");
      } else if (key.escape) {
        setAnnotateMode(false);
        setAnnotateBuffer("");
      } else if (key.backspace || key.delete) {
        setAnnotateBuffer((b) => b.slice(0, -1));
      } else if (input && !key.ctrl && !key.meta) {
        setAnnotateBuffer((b) => b + input);
      }
      return;
    }

    // Navigation
    if (key.upArrow) {
      setSelectedIdx((i) => Math.max(0, i - 1));
    } else if (key.downArrow) {
      setSelectedIdx((i) => Math.min(threats.length - 1, i + 1));
    } else if (input === "d" && threat) {
      // Dismiss
      const dismissed = [...(model.dismissedThreats ?? [])];
      if (!dismissed.includes(threat.id)) {
        dismissed.push(threat.id);
      }
      setModel({ ...model, dismissedThreats: dismissed });
    } else if (input === "m" && threat) {
      // Mark mitigated
      const confirmed = [...(model.confirmedMitigations ?? [])];
      const mitigation = `${threat.title} (operator-confirmed)`;
      if (!confirmed.includes(mitigation)) {
        confirmed.push(mitigation);
      }
      // Remove from dismissed if it was there
      const dismissed = (model.dismissedThreats ?? []).filter((id) => id !== threat.id);
      setModel({ ...model, confirmedMitigations: confirmed, dismissedThreats: dismissed });
    } else if (input === "r" && threat) {
      // Restore
      const dismissed = (model.dismissedThreats ?? []).filter((id) => id !== threat.id);
      const confirmed = (model.confirmedMitigations ?? []).filter(
        (m) => !m.includes(threat.title),
      );
      setModel({ ...model, dismissedThreats: dismissed, confirmedMitigations: confirmed });
    } else if (input === "a" && threat) {
      // Annotate
      setAnnotateMode(true);
      setAnnotateBuffer(model.userAnnotations?.[threat.id] ?? "");
    } else if (input === "q" || key.escape) {
      finish();
    } else if (input === "S") {
      onSkip();
    }
  });

  if (threats.length === 0) {
    return (
      <Box flexDirection="column">
        <Text>{""}</Text>
        <Text>{boxHeader("Threat Model Editor", width)}</Text>
        <Text>{""}</Text>
        <Text>{"  "}{chalk.dim("No threats in threat model. Press [q] to continue.")}</Text>
        <Text>{""}</Text>
        <Text>{boxFooter(width)}</Text>
      </Box>
    );
  }

  // Summary counts
  const activeCount = threats.filter((t) => getThreatStatus(t, model) === "active").length;
  const dismissedCount = threats.filter((t) => getThreatStatus(t, model) === "dismissed").length;
  const mitigatedCount = threats.filter((t) => getThreatStatus(t, model) === "mitigated").length;

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxHeader(`Threat Model Editor (${threats.length} threats)`, width)}</Text>
      <Text>{""}</Text>

      {/* Summary bar */}
      <Text>
        {"  "}{chalk.green(`${activeCount} active`)}  {chalk.dim(`${dismissedCount} dismissed`)}  {chalk.blue(`${mitigatedCount} mitigated`)}
      </Text>
      <Text>{""}</Text>

      {/* Threat list */}
      {visibleThreats.map((t, vi) => {
        const realIdx = scrollStart + vi;
        const isSelected = realIdx === selectedIdx;
        const status = getThreatStatus(t, model);
        const cursor = isSelected ? chalk.cyan("> ") : "  ";
        const annotation = model.userAnnotations?.[t.id];
        const badge = statusBadge(status);

        const titleText = status === "dismissed"
          ? chalk.strikethrough.dim(t.title)
          : isSelected
            ? chalk.white.bold(t.title)
            : chalk.white(t.title);

        return (
          <Box key={t.id} flexDirection="column">
            <Text>{cursor}{chalk.dim(t.id)}  {titleText}  {badge}</Text>
            <Text>
              {"     "}{icons.bullet} {impactBadge(t.impact)}  {chalk.dim("likelihood:")} {t.likelihood}  {categoryLabel(t.category)}
            </Text>
            {isSelected && (
              <>
                {t.attackVector && (
                  <Text>{"     "}{chalk.dim("Attack:")} {t.attackVector.slice(0, 70)}{t.attackVector.length > 70 ? "..." : ""}</Text>
                )}
                {t.existingMitigations.length > 0 && (
                  <Text>{"     "}{chalk.green("Mitigations:")} {t.existingMitigations.join(", ")}</Text>
                )}
                {t.missingMitigations.length > 0 && (
                  <Text>{"     "}{chalk.yellow("Missing:")} {t.missingMitigations.join(", ")}</Text>
                )}
                {annotation && (
                  <Text>{"     "}{chalk.cyan("Note:")} {annotation}</Text>
                )}
              </>
            )}
            {!isSelected && vi < visibleThreats.length - 1 && <Text>{""}</Text>}
            {isSelected && <Text>{""}</Text>}
          </Box>
        );
      })}

      {/* Scroll indicator */}
      {threats.length > VISIBLE_COUNT && (
        <Text>{"  "}{chalk.dim(`Showing ${scrollStart + 1}-${Math.min(scrollStart + VISIBLE_COUNT, threats.length)} of ${threats.length}`)}</Text>
      )}

      {/* Annotation input */}
      {annotateMode && (
        <Box marginTop={1}>
          <Text>{"  "}{chalk.cyan("Note:")} {annotateBuffer}{chalk.cyan("\u2588")}</Text>
        </Box>
      )}

      <Text>{""}</Text>
      <Text>
        {"  "}{chalk.dim("[↑↓]")} navigate  {chalk.blue.bold("[m]")} mitigate  {chalk.red.bold("[d]")} dismiss  {chalk.green.bold("[r]")} restore
      </Text>
      <Text>
        {"  "}{chalk.cyan.bold("[a]")} annotate  {chalk.dim("[q]")} done  {chalk.dim("[S]")} skip
      </Text>
      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}

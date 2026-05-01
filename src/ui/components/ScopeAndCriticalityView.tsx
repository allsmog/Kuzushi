/**
 * ScopeAndCriticalityView — Phase C.4 scope, calibration, and operator edits.
 *
 * Three stacked sections:
 *
 *   1. Criticality buckets (`narrative.criticalityBuckets`) — four columns
 *      (critical / high / medium / low) listing concrete examples of what
 *      counts as each severity for this application. Randori emits these
 *      as a "calibration" layer so reviewers can check whether the labels
 *      match the product's actual risk posture.
 *
 *   2. Out-of-scope (`narrative.outOfScope`) — bulleted list of classes
 *      of issues the model explicitly excludes. Helps reviewers see the
 *      assumptions rather than inferring them.
 *
 *   3. Operator edits — `userAnnotations`, `confirmedMitigations`, and
 *      `dismissedThreats`. Each entry gets a dirty-dot (●) marker so
 *      operators can tell their overrides are active when they look at
 *      the view again later.
 */

import { Box, Text } from "ink";
import type React from "react";
import type {
  ThreatModelCriticalityBuckets,
  ThreatModelDocument,
} from "../../agents/tasks/threat-modeling/types.js";
import { formatThreatModelSource } from "../../copilot/threat-model-loader.js";
import { truncateEnd } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { useTerminalSize } from "../hooks/useTerminalSize.js";
import type { ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { ContextStrip } from "./ContextStrip.js";
import { EmptyState as EmptyStateCard } from "./EmptyState.js";
import { ScreenContent } from "./ScreenContent.js";

interface ScopeAndCriticalityViewProps {
  shell: ShellState;
}

export function ScopeAndCriticalityView({
  shell,
}: ScopeAndCriticalityViewProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "1", label: "dfd", secondary: true },
    { keys: "2", label: "stride", secondary: true },
    { keys: "3", label: "stories", secondary: true },
    { keys: "4", label: "scope" },
    { keys: "5", label: "summary", secondary: true },
    { keys: "/threats edit", label: "annotate", secondary: true },
    { keys: "q", label: "back", secondary: true },
  ]);
  const tm = shell.threatModel;
  const { columns } = useTerminalSize();
  // Bullet rows reflow to terminal width with sane bounds so 80-col stays
  // readable and 200-col stops eating empty pane.
  const lineWidth = Math.max(40, Math.min(columns - 8, 110));
  const itemWidth = Math.max(40, Math.min(columns - 12, 110));
  const noteWidth = Math.max(32, Math.min(columns - 28, 90));
  if (!tm) return <EmptyState />;

  const buckets = tm.narrative?.criticalityBuckets;
  const outOfScope = tm.narrative?.outOfScope ?? [];
  const edits = summariseEdits(tm);

  return (
    <ScreenContent>
      <ContextStrip
        status={[`${edits.total} operator edits`]}
        subtitle={
          shell.threatModelSource
            ? formatThreatModelSource({
                sourcePath: shell.threatModelSource.path,
                mtimeMs: shell.threatModelSource.mtimeMs,
              })
            : undefined
        }
      />

      {buckets ? <CriticalityBuckets buckets={buckets} itemWidth={itemWidth} /> : null}

      {outOfScope.length > 0 ? (
        <Box flexDirection="column" marginTop={SPACING.sm}>
          <Text>{tokens.label("out of scope")}</Text>
          <Box flexDirection="column" paddingLeft={SPACING.lg} marginTop={SPACING.sm}>
            {outOfScope.map((line) => (
              <Text key={`oos-${stableTextKey(line)}`}>
                {tokens.muted("\u00B7  ")}
                {tokens.muted(truncateEnd(line, lineWidth))}
              </Text>
            ))}
          </Box>
        </Box>
      ) : null}

      <OperatorEdits tm={tm} itemWidth={itemWidth} noteWidth={noteWidth} />
    </ScreenContent>
  );
}

function EmptyState(): React.ReactElement {
  return (
    <ScreenContent>
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong("scope & criticality")}
      </Text>
      <Box marginTop={SPACING.sm}>
        <EmptyStateCard kind="threat-model-missing" context={{ threatView: "scope" }} />
      </Box>
    </ScreenContent>
  );
}

function CriticalityBuckets({
  buckets,
  itemWidth,
}: {
  buckets: ThreatModelCriticalityBuckets;
  itemWidth: number;
}): React.ReactElement {
  const order: Array<keyof ThreatModelCriticalityBuckets> = ["critical", "high", "medium", "low"];
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("criticality calibration")}</Text>
      <Box flexDirection="column" paddingLeft={SPACING.lg} marginTop={SPACING.sm}>
        {order.map((tier) => (
          <Box key={tier} flexDirection="column" marginBottom={SPACING.sm}>
            <Text>
              {severityBadge(tier)}
              {"  "}
              {tokens.muted(
                `${buckets[tier]?.length ?? 0} example${(buckets[tier]?.length ?? 0) === 1 ? "" : "s"}`,
              )}
            </Text>
            {(buckets[tier] ?? []).slice(0, 5).map((item) => (
              <Text key={`${tier}-${stableTextKey(item)}`}>
                {"   "}
                {tokens.muted("\u00B7")}
                {"  "}
                {tokens.muted(truncateEnd(item, itemWidth))}
              </Text>
            ))}
            {(buckets[tier] ?? []).length > 5 ? (
              <Text>
                {"   "}
                {tokens.hint(`\u00B7  (+${(buckets[tier] ?? []).length - 5} more)`)}
              </Text>
            ) : null}
          </Box>
        ))}
      </Box>
    </Box>
  );
}

function severityBadge(tier: keyof ThreatModelCriticalityBuckets): string {
  switch (tier) {
    case "critical":
      return tokens.dangerStrong("CRIT");
    case "high":
      return tokens.danger("HIGH");
    case "medium":
      return tokens.warn("MED ");
    case "low":
      return tokens.info("LOW ");
  }
}

function OperatorEdits({
  tm,
  itemWidth,
  noteWidth,
}: {
  tm: ThreatModelDocument;
  itemWidth: number;
  noteWidth: number;
}): React.ReactElement {
  const annotations = Object.entries(tm.userAnnotations ?? {});
  const confirmed = tm.confirmedMitigations ?? [];
  const dismissed = tm.dismissedThreats ?? [];

  const total = annotations.length + confirmed.length + dismissed.length;
  if (total === 0) {
    return (
      <Box flexDirection="column" marginTop={SPACING.sm}>
        <Text>{tokens.label("operator edits")}</Text>
        <Box marginTop={SPACING.sm}>
          <Text>
            {tokens.muted(
              "   (no operator overrides yet — use /threats edit to annotate or dismiss)",
            )}
          </Text>
        </Box>
      </Box>
    );
  }

  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("operator edits")}</Text>

      {annotations.length > 0 ? (
        <Box flexDirection="column" marginTop={SPACING.sm} paddingLeft={SPACING.lg}>
          <Text>
            {tokens.accent("\u25CF  ")}
            {tokens.strong(`annotations (${annotations.length})`)}
          </Text>
          {annotations.slice(0, 6).map(([id, note]) => (
            <Text key={`ann-${id}`}>
              {"   "}
              {tokens.muted(`[${id}]`)}
              {"  "}
              {tokens.muted(truncateEnd(note, noteWidth))}
            </Text>
          ))}
          {annotations.length > 6 ? (
            <Text>
              {"   "}
              {tokens.hint(`(+${annotations.length - 6} more)`)}
            </Text>
          ) : null}
        </Box>
      ) : null}

      {confirmed.length > 0 ? (
        <Box flexDirection="column" marginTop={SPACING.sm} paddingLeft={SPACING.lg}>
          <Text>
            {tokens.success("\u25CF  ")}
            {tokens.strong(`confirmed mitigations (${confirmed.length})`)}
          </Text>
          {confirmed.slice(0, 6).map((item) => (
            <Text key={`mit-${stableTextKey(item)}`}>
              {"   "}
              {tokens.muted("\u00B7  ")}
              {tokens.value(truncateEnd(item, itemWidth))}
            </Text>
          ))}
          {confirmed.length > 6 ? (
            <Text>
              {"   "}
              {tokens.hint(`\u00B7  (+${confirmed.length - 6} more)`)}
            </Text>
          ) : null}
        </Box>
      ) : null}

      {dismissed.length > 0 ? (
        <Box flexDirection="column" marginTop={SPACING.sm} paddingLeft={SPACING.lg}>
          <Text>
            {tokens.warn("\u25CF  ")}
            {tokens.strong(`dismissed threats (${dismissed.length})`)}
          </Text>
          <Text>
            {"   "}
            {tokens.muted(truncateEnd(dismissed.slice(0, 10).join(", "), itemWidth))}
            {dismissed.length > 10 ? tokens.hint(`  (+${dismissed.length - 10} more)`) : ""}
          </Text>
        </Box>
      ) : null}

      {tm.lastEditedAt ? (
        <Box marginTop={SPACING.sm}>
          <Text>{tokens.hint(`   last edit: ${tm.lastEditedAt}`)}</Text>
        </Box>
      ) : null}
    </Box>
  );
}

function summariseEdits(tm: ThreatModelDocument): { total: number } {
  const total =
    Object.keys(tm.userAnnotations ?? {}).length +
    (tm.confirmedMitigations?.length ?? 0) +
    (tm.dismissedThreats?.length ?? 0);
  return { total };
}

function stableTextKey(value: string): string {
  let hash = 0;
  for (let i = 0; i < value.length; i += 1) {
    hash = (hash * 31 + value.charCodeAt(i)) >>> 0;
  }
  return hash.toString(36);
}

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
import type { ShellState } from "../state.js";
import { tokens } from "../tokens.js";
import { EmptyState as EmptyStateCard } from "./EmptyState.js";
import { ShellFooterHints } from "./ShellFooterHints.js";

interface ScopeAndCriticalityViewProps {
  shell: ShellState;
}

export function ScopeAndCriticalityView({
  shell,
}: ScopeAndCriticalityViewProps): React.ReactElement {
  const tm = shell.threatModel;
  if (!tm) return <EmptyState />;

  const buckets = tm.narrative?.criticalityBuckets;
  const outOfScope = tm.narrative?.outOfScope ?? [];
  const edits = summariseEdits(tm);

  return (
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <Header shell={shell} editCount={edits.total} />

      {buckets ? <CriticalityBuckets buckets={buckets} /> : null}

      {outOfScope.length > 0 ? (
        <Box flexDirection="column" marginTop={1}>
          <Text>{tokens.label("out of scope")}</Text>
          <Box flexDirection="column" paddingLeft={3} marginTop={1}>
            {outOfScope.map((line, i) => (
              <Text key={`oos-${i}-${line.slice(0, 6)}`}>
                {tokens.muted("\u00B7  ")}
                {tokens.muted(truncate(line, 74))}
              </Text>
            ))}
          </Box>
        </Box>
      ) : null}

      <OperatorEdits tm={tm} />

      <HintFooter />
    </Box>
  );
}

function EmptyState(): React.ReactElement {
  return (
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong("scope & criticality")}
      </Text>
      <Box marginTop={1}>
        <EmptyStateCard kind="threat-model-missing" context={{ threatView: "scope" }} />
      </Box>
    </Box>
  );
}

function Header({
  shell,
  editCount,
}: {
  shell: ShellState;
  editCount: number;
}): React.ReactElement {
  return (
    <Box flexDirection="column">
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong("scope & criticality")}
        {tokens.muted("   \u2502   ")}
        {editCount > 0
          ? tokens.value(`${editCount} operator edit${editCount === 1 ? "" : "s"}`)
          : tokens.muted("no operator edits yet")}
      </Text>
      {shell.threatModelSource ? (
        <Text>
          {tokens.hint(
            formatThreatModelSource({
              sourcePath: shell.threatModelSource.path,
              mtimeMs: shell.threatModelSource.mtimeMs,
            }),
          )}
        </Text>
      ) : null}
    </Box>
  );
}

function CriticalityBuckets({
  buckets,
}: {
  buckets: ThreatModelCriticalityBuckets;
}): React.ReactElement {
  const order: Array<keyof ThreatModelCriticalityBuckets> = ["critical", "high", "medium", "low"];
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text>{tokens.label("criticality calibration")}</Text>
      <Box flexDirection="column" paddingLeft={3} marginTop={1}>
        {order.map((tier) => (
          <Box key={tier} flexDirection="column" marginBottom={1}>
            <Text>
              {severityBadge(tier)}
              {"  "}
              {tokens.muted(
                `${buckets[tier]?.length ?? 0} example${(buckets[tier]?.length ?? 0) === 1 ? "" : "s"}`,
              )}
            </Text>
            {(buckets[tier] ?? []).slice(0, 5).map((item, i) => (
              <Text key={`${tier}-${i}`}>
                {"   "}
                {tokens.muted("\u00B7")}
                {"  "}
                {tokens.muted(truncate(item, 70))}
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

function OperatorEdits({ tm }: { tm: ThreatModelDocument }): React.ReactElement {
  const annotations = Object.entries(tm.userAnnotations ?? {});
  const confirmed = tm.confirmedMitigations ?? [];
  const dismissed = tm.dismissedThreats ?? [];

  const total = annotations.length + confirmed.length + dismissed.length;
  if (total === 0) {
    return (
      <Box flexDirection="column" marginTop={1}>
        <Text>{tokens.label("operator edits")}</Text>
        <Box marginTop={1}>
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
    <Box flexDirection="column" marginTop={1}>
      <Text>{tokens.label("operator edits")}</Text>

      {annotations.length > 0 ? (
        <Box flexDirection="column" marginTop={1} paddingLeft={3}>
          <Text>
            {tokens.accent("\u25CF  ")}
            {tokens.strong(`annotations (${annotations.length})`)}
          </Text>
          {annotations.slice(0, 6).map(([id, note]) => (
            <Text key={`ann-${id}`}>
              {"   "}
              {tokens.muted(`[${id}]`)}
              {"  "}
              {tokens.muted(truncate(note, 60))}
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
        <Box flexDirection="column" marginTop={1} paddingLeft={3}>
          <Text>
            {tokens.success("\u25CF  ")}
            {tokens.strong(`confirmed mitigations (${confirmed.length})`)}
          </Text>
          {confirmed.slice(0, 6).map((item, i) => (
            <Text key={`mit-${i}`}>
              {"   "}
              {tokens.muted("\u00B7  ")}
              {tokens.value(truncate(item, 70))}
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
        <Box flexDirection="column" marginTop={1} paddingLeft={3}>
          <Text>
            {tokens.warn("\u25CF  ")}
            {tokens.strong(`dismissed threats (${dismissed.length})`)}
          </Text>
          <Text>
            {"   "}
            {tokens.muted(dismissed.slice(0, 10).join(", "))}
            {dismissed.length > 10 ? tokens.hint(`  (+${dismissed.length - 10} more)`) : ""}
          </Text>
        </Box>
      ) : null}

      {tm.lastEditedAt ? (
        <Box marginTop={1}>
          <Text>{tokens.hint(`   last edit: ${tm.lastEditedAt}`)}</Text>
        </Box>
      ) : null}
    </Box>
  );
}

function HintFooter(): React.ReactElement {
  // `1..5` cycle across threat views (shared logic in `resolveThreatView`);
  // `/threats edit` opens the full editor; `q` and `/back` step up.
  return (
    <ShellFooterHints
      hints={[
        { key: "1", label: "dfd" },
        { key: "2", label: "stride" },
        { key: "3", label: "stories" },
        { key: "4", label: "scope" },
        { key: "5", label: "summary" },
        { key: "/threats edit", label: "annotate" },
        { key: "q", label: "back" },
      ]}
    />
  );
}

function summariseEdits(tm: ThreatModelDocument): { total: number } {
  const total =
    Object.keys(tm.userAnnotations ?? {}).length +
    (tm.confirmedMitigations?.length ?? 0) +
    (tm.dismissedThreats?.length ?? 0);
  return { total };
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}\u2026`;
}

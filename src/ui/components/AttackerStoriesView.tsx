/**
 * AttackerStoriesView — Phase C.3 narrative cards.
 *
 * Renders the randori narrative layer in two columns:
 *   - Left rail: the six `inputCategories` (attacker/operator/developer/
 *     external/sandbox/assumptions) as short labelled lists. This is the
 *     trust-boundary side of the story: what inputs the system actually
 *     accepts.
 *   - Right column: one card per `narrative.attackerStories[]` with the
 *     title, 2-4 sentence narrative, current mitigation, and chips for
 *     any linked `threatIds` (muted "(unmapped)" when absent).
 *
 * The narrative block is the most "human" part of randori's output —
 * this view is intentionally text-dense so operators can read the story
 * without hopping between screens.
 */

import { Box, Text } from "ink";
import type React from "react";
import type {
  ThreatModelAttackerStory,
  ThreatModelInputCategories,
} from "../../agents/tasks/threat-modeling/types.js";
import { formatThreatModelSource } from "../../copilot/threat-model-loader.js";
import { truncateEnd } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import type { ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { ContextStrip } from "./ContextStrip.js";
import { EmptyState as EmptyStateCard } from "./EmptyState.js";
import { ScreenContent } from "./ScreenContent.js";

const INPUT_CATEGORY_ORDER: Array<{
  key: keyof ThreatModelInputCategories;
  label: string;
}> = [
  { key: "attackerControlled", label: "attacker-controlled" },
  { key: "operatorControlled", label: "operator-controlled" },
  { key: "developerControlled", label: "developer-controlled" },
  { key: "externalServices", label: "external services" },
  { key: "sandboxBoundary", label: "sandbox boundary" },
  { key: "assumptions", label: "assumptions" },
];

interface AttackerStoriesViewProps {
  shell: ShellState;
}

export function AttackerStoriesView({ shell }: AttackerStoriesViewProps): React.ReactElement {
  useRegisterKeybindings([
    { keys: "1", label: "dfd", secondary: true },
    { keys: "2", label: "stride", secondary: true },
    { keys: "3", label: "stories" },
    { keys: "4", label: "scope", secondary: true },
    { keys: "5", label: "summary", secondary: true },
    { keys: "q", label: "back", secondary: true },
  ]);
  const tm = shell.threatModel;
  if (!tm) return <EmptyState />;

  const narrative = tm.narrative;
  const stories = narrative?.attackerStories ?? [];
  const inputs = narrative?.inputCategories;

  return (
    <ScreenContent>
      <ContextStrip
        status={[`${stories.length} stories`, `${tm.threats.length} threats`]}
        subtitle={
          shell.threatModelSource
            ? formatThreatModelSource({
                sourcePath: shell.threatModelSource.path,
                mtimeMs: shell.threatModelSource.mtimeMs,
              })
            : undefined
        }
      />

      {narrative?.overview ? (
        <Box flexDirection="column" marginTop={SPACING.sm}>
          <Text>{tokens.label("overview")}</Text>
          <Box paddingLeft={SPACING.lg} flexDirection="column" marginTop={SPACING.sm}>
            {wrap(narrative.overview, 72).map((line, i) => (
              <Text key={`${i}-${line.slice(0, 6)}`}>{tokens.value(line)}</Text>
            ))}
          </Box>
        </Box>
      ) : null}

      {inputs ? <InputCategoriesRail inputs={inputs} /> : null}

      <Box flexDirection="column" marginTop={SPACING.sm}>
        <Text>{tokens.label(`attacker stories (${stories.length})`)}</Text>
        {stories.length === 0 ? (
          <Box marginTop={SPACING.sm}>
            <Text>
              {tokens.muted("   (randori didn't emit any attacker stories for this model)")}
            </Text>
          </Box>
        ) : (
          <Box flexDirection="column" marginTop={SPACING.sm}>
            {stories.map((story, i) => (
              <StoryCard key={`${i}-${story.title}`} story={story} />
            ))}
          </Box>
        )}
      </Box>
    </ScreenContent>
  );
}

function EmptyState(): React.ReactElement {
  return (
    <ScreenContent>
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong("attacker stories")}
      </Text>
      <Box marginTop={SPACING.sm}>
        <EmptyStateCard kind="threat-model-missing" context={{ threatView: "stories" }} />
      </Box>
    </ScreenContent>
  );
}

function InputCategoriesRail({
  inputs,
}: {
  inputs: ThreatModelInputCategories;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={SPACING.sm}>
      <Text>{tokens.label("input categories")}</Text>
      <Box flexDirection="column" marginTop={SPACING.sm} paddingLeft={SPACING.lg}>
        {INPUT_CATEGORY_ORDER.map(({ key, label }) => {
          const items = inputs[key];
          if (!items || items.length === 0) {
            return <Text key={key}>{tokens.muted(`${label.padEnd(22)}  (none listed)`)}</Text>;
          }
          return (
            <Box key={key} flexDirection="column" marginBottom={SPACING.sm}>
              <Text>
                {tokens.value(label.padEnd(22))}
                {tokens.muted(`${items.length} entries`)}
              </Text>
              {items.slice(0, 4).map((entry, i) => (
                <Text key={`${key}-${i}`}>
                  {"   "}
                  {tokens.muted("\u00B7")}
                  {"  "}
                  {tokens.muted(truncateEnd(entry, 68))}
                </Text>
              ))}
              {items.length > 4 ? (
                <Text>
                  {"   "}
                  {tokens.hint(`\u00B7  (+${items.length - 4} more)`)}
                </Text>
              ) : null}
            </Box>
          );
        })}
      </Box>
    </Box>
  );
}

function StoryCard({ story }: { story: ThreatModelAttackerStory }): React.ReactElement {
  const width = 74;
  const bar = "\u2500".repeat(width - 4);
  return (
    <Box flexDirection="column" marginBottom={SPACING.sm}>
      <Text>
        {tokens.muted("   \u256D\u2500 ")}
        {tokens.strong(truncateEnd(story.title, width - 8))}
        {tokens.muted(` ${bar.slice(0, Math.max(0, width - story.title.length - 4))}\u256E`)}
      </Text>

      {wrap(story.narrative, width - 4).map((line, i) => (
        <Text key={`n-${i}-${line.slice(0, 6)}`}>
          {tokens.muted("   \u2502 ")}
          {tokens.value(line)}
        </Text>
      ))}

      {story.mitigation ? (
        <>
          <Text>{tokens.muted("   \u2502 ")}</Text>
          <Text>
            {tokens.muted("   \u2502 ")}
            {tokens.label("mitigation: ")}
            {tokens.muted(truncateEnd(story.mitigation, width - 18))}
          </Text>
        </>
      ) : null}

      <Text>
        {tokens.muted("   \u2502 ")}
        {renderThreatChips(story.threatIds)}
      </Text>

      <Text>{tokens.muted(`   \u2570${"\u2500".repeat(width - 2)}\u256F`)}</Text>
    </Box>
  );
}

function renderThreatChips(threatIds: ReadonlyArray<string> | undefined): string {
  if (!threatIds || threatIds.length === 0) {
    return tokens.hint("(unmapped — no linked STRIDE threats)");
  }
  const chips = threatIds.slice(0, 6).map((id) => tokens.info(`[${id}]`));
  const extra = threatIds.length > 6 ? tokens.muted(`  +${threatIds.length - 6} more`) : "";
  return `${chips.join(" ")}${extra}`;
}

function wrap(text: string, width: number): string[] {
  const lines: string[] = [];
  for (const paragraph of text.split(/\n+/)) {
    if (paragraph.length === 0) {
      lines.push("");
      continue;
    }
    const words = paragraph.split(/\s+/);
    let current = "";
    for (const word of words) {
      const next = current.length === 0 ? word : `${current} ${word}`;
      if (next.length > width && current.length > 0) {
        lines.push(current);
        current = word;
      } else {
        current = next;
      }
    }
    if (current) lines.push(current);
  }
  return lines;
}

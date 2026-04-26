/**
 * BannerSplash — Phase D.2 one-shot "welcome" header rendered at shell boot.
 *
 * Stays intentionally light: a compact ASCII wordmark, an identity line,
 * and a rotating "tip of the day" picked deterministically from the
 * operator's boot timestamp so two boots in the same minute show the
 * same tip (less jarring than strict random).
 *
 * Rendered once (via Ink <Static>) at the very top of CopilotShell so it
 * scrolls away naturally as the session fills in. Non-TTY callers skip
 * it — the plain-renderer emits one line of "kuzushi shell (ws=…)" so
 * log transcripts stay compact.
 */

import { Box, Text, useStdout } from "ink";
import type React from "react";
import { truncateEnd, truncateMiddle } from "../format.js";
import { SPACING, tokens } from "../tokens.js";

const WORDMARK = [
  "  ██╗  ██╗██╗   ██╗███████╗██╗   ██╗███████╗██╗  ██╗██╗",
  "  ██║ ██╔╝██║   ██║╚══███╔╝██║   ██║██╔════╝██║  ██║██║",
  "  █████╔╝ ██║   ██║  ███╔╝ ██║   ██║███████╗███████║██║",
  "  ██╔═██╗ ██║   ██║ ███╔╝  ██║   ██║╚════██║██╔══██║██║",
  "  ██║  ██╗╚██████╔╝███████╗╚██████╔╝███████║██║  ██║██║",
  "  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝",
] as const;

const TIPS: ReadonlyArray<string> = [
  'type /plan "run harder, focus on auth" to have Haiku propose option changes',
  "/prompt edit triage opens the triage prompt override in $EDITOR",
  "/show runs lists every past scan; /replay <id> re-renders the summary",
  "/threats dfd — ASCII box-and-arrow of the randori data flow diagram (1..5 to cycle)",
  "F-0001 / C-01 short-IDs resolve deterministically — /show aliases to list them",
  "house rules live at .kuzushi/house-rules/<moduleId>.md and round-trip with git",
  "two-stage Ctrl+C at the prompt: once to arm, again within 2s to exit",
  "kuzushi scan . --ci disables Ink and writes one line per stage transition",
  "/tune shows six plain controls; press p or /config for the full editor",
  "/trace <runId> streams the per-event JSONL audit log of a past scan",
];

interface BannerSplashProps {
  /** Workspace / target context — shown below the wordmark when present. */
  workspace?: string | null;
  target?: string | null;
  /** Override the tip shown. Primarily a test hook. */
  tip?: string;
}

export function BannerSplash({ workspace, target, tip }: BannerSplashProps): React.ReactElement {
  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 100;
  const textWidth = Math.max(24, columns - SPACING.md * 2 - 4);
  const resolvedTip = tip ?? pickTip(`${workspace ?? ""}\u0000${target ?? ""}`);
  const contextParts: string[] = [];
  if (workspace) contextParts.push(`workspace ${workspace}`);
  if (target) contextParts.push(`target ${truncateMiddle(target, Math.min(48, textWidth - 7))}`);
  const contextLine = truncateEnd(contextParts.join("  \u00B7  "), textWidth);
  const tipLine = truncateEnd(resolvedTip, textWidth - "tip: ".length);

  return (
    <Box
      flexDirection="column"
      paddingLeft={SPACING.md}
      marginTop={SPACING.sm}
      marginBottom={SPACING.sm}
    >
      {WORDMARK.map((row) => (
        <Text key={row}>{tokens.accent(row)}</Text>
      ))}
      <Box marginTop={SPACING.sm}>
        <Text>
          {tokens.muted("  \u5D29\u3057 \u2014 ")}
          {tokens.strong("Kuzushi")}
          {tokens.muted(" \u2014 agentic SAST orchestration")}
        </Text>
      </Box>
      {contextParts.length > 0 ? (
        <Box>
          <Text>
            {tokens.muted("  ")}
            {tokens.muted(contextLine)}
          </Text>
        </Box>
      ) : null}
      <Box marginTop={SPACING.sm}>
        <Text>
          {tokens.hint("  tip: ")}
          {tokens.hint(tipLine)}
        </Text>
      </Box>
    </Box>
  );
}

/**
 * Deterministic tip pick:
 * - numeric seeds preserve the legacy "same minute => same tip" behavior
 * - string seeds hash stable shell context such as workspace/target
 */
export function pickTip(seed: number | string): string {
  const basis =
    typeof seed === "number"
      ? Math.floor(seed / 60_000)
      : [...seed].reduce((acc, ch) => (acc * 33 + ch.charCodeAt(0)) >>> 0, 5381);
  const idx = Math.abs(basis) % TIPS.length;
  return TIPS[idx]!;
}

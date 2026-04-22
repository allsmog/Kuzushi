/**
 * Rate-limit banner — one-line advisory shown while the adaptive
 * concurrency registry has the pipeline throttled.
 *
 * Phase B.4 introduced the surface; Workstream 3 tightened the copy so
 * operators see both a concrete recovery verb (`/concurrency <n>`) and
 * an "until" timestamp when the upstream provider gave us a retry-after.
 *
 * Reads `state.throttle` directly (already populated by
 * `src/scheduler/rate-limit-registry.ts` on 429 responses). Auto-hides
 * when throttle clears, so the banner is self-timing — the registry
 * decides when the scan is back to normal.
 */

import { Box, Text } from "ink";
import type React from "react";
import { icons } from "../icons.js";
import { tokens } from "../tokens.js";

interface RateLimitBannerProps {
  throttle?: {
    concurrency: number;
    reason: string;
    /** Epoch ms the registry expects to lift the throttle. Optional. */
    until?: number;
  } | null;
  /** Injectable clock for tests. Defaults to `Date.now`. */
  now?: () => number;
}

export function RateLimitBanner({
  throttle,
  now = Date.now,
}: RateLimitBannerProps): React.ReactElement | null {
  if (!throttle) return null;

  const untilStr = formatUntil(throttle.until, now());
  // Suggest halving concurrency, min 1 — safe heuristic when the provider
  // is clearly rate-limiting us.
  const suggested = Math.max(1, Math.floor(throttle.concurrency / 2));

  return (
    <Box flexDirection="column" marginBottom={1} paddingLeft={2}>
      <Text>
        {tokens.warnStrong(`${icons.warning} rate-limited`)}
        {tokens.muted(
          `  ·  concurrency reduced to ${throttle.concurrency}${
            untilStr ? `  ·  retrying ${untilStr}` : ""
          }`,
        )}
      </Text>
      {throttle.reason ? (
        <Text>{tokens.muted(`    ${throttle.reason}`)}</Text>
      ) : null}
      <Text>
        {tokens.hint(
          `    use /concurrency ${suggested} to back off further, or wait for auto-recovery`,
        )}
      </Text>
    </Box>
  );
}

/**
 * Format the `until` timestamp as a short relative string ("in 42s") when
 * it's in the near future, or HH:MM when it's further out. Returns the
 * empty string when we don't have a reliable timestamp — the banner just
 * omits the "retrying …" clause.
 */
export function formatUntil(until: number | undefined, nowMs: number): string {
  if (!until || !Number.isFinite(until) || until <= nowMs) return "";
  const deltaMs = until - nowMs;
  const deltaSec = Math.round(deltaMs / 1000);
  if (deltaSec < 120) return `in ${deltaSec}s`;
  if (deltaSec < 3600) return `in ${Math.round(deltaSec / 60)}m`;
  // Longer throttles — render wall-clock HH:MM instead of "in 4h".
  const d = new Date(until);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `at ${hh}:${mm}`;
}

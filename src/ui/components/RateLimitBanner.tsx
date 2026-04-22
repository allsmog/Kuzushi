/**
 * Rate-limit banner — one-line advisory shown while the adaptive
 * concurrency registry has the pipeline throttled.
 *
 * Phase B.4. Reads `state.throttle` directly (already populated by
 * src/scheduler/rate-limit-registry.ts on 429 responses). Auto-hides
 * when throttle clears, so the banner is self-timing — the registry
 * decides when the scan is back to normal.
 */

import { Box, Text } from "ink";
import type React from "react";
import { icons } from "../icons.js";
import { tokens } from "../tokens.js";

interface RateLimitBannerProps {
  throttle?: { concurrency: number; reason: string } | null;
}

export function RateLimitBanner({ throttle }: RateLimitBannerProps): React.ReactElement | null {
  if (!throttle) return null;
  return (
    <Box marginBottom={1} paddingLeft={2}>
      <Text>
        {tokens.warn(icons.warning)}
        {"  "}
        {tokens.warnStrong("rate limited")}
        {tokens.tertiary(`  ·  ${throttle.concurrency} concurrent`)}
        {throttle.reason ? tokens.tertiary(`  ·  ${throttle.reason}`) : ""}
        {tokens.hint("  · adapting")}
      </Text>
    </Box>
  );
}

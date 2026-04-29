/**
 * RuleHeader — generic header for the new TUI views.
 *
 * Renders one breadcrumb line (left) plus an optional right-aligned status
 * blob, followed by a horizontal `Divider`. Used by ModuleRunView,
 * ActorTranscriptView, PromptsEditorView, and (after polish) ThreatDfdView
 * so every page wears the same hat.
 *
 * Intentionally narrow API — no nested boxes, no severity coloring, just
 * the muted breadcrumb / value status / single rule stack the mocks call
 * for. Keep it that way: extra knobs belong in the view component.
 */
import { Box, Text } from "ink";
import type React from "react";
import { Divider } from "../primitives/Divider.js";
import { SPACING, tokens } from "../tokens.js";

export interface RuleHeaderProps {
  /** Path-style breadcrumb, e.g. `kuzushi/carlini-threat-hunt/run`. */
  breadcrumb: string;
  /** Optional right-aligned status, e.g. `12s · running`. */
  status?: string;
  /**
   * Show the underline rule. Defaults `true`; pass `false` for screens
   * that already have a Section divider directly below the header.
   */
  rule?: boolean;
}

export function RuleHeader({
  breadcrumb,
  status,
  rule = true,
}: RuleHeaderProps): React.ReactElement {
  return (
    <Box flexDirection="column" marginBottom={SPACING.sm}>
      <Box justifyContent="space-between">
        <Text>{tokens.muted(breadcrumb)}</Text>
        {status ? <Text>{tokens.value(status)}</Text> : null}
      </Box>
      {rule ? <Divider /> : null}
    </Box>
  );
}

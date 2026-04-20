/**
 * Placeholder rendering for the Phase C threat-model views.
 *
 * C.0 ships the loader, state field, and verb routing; C.1–C.5 each drop
 * a real component that replaces one branch of `ShellViewPanel`. Until
 * then, any `/threats <view>` verb lands here so the routing is fully
 * exercised in unit tests without requiring the visual components to
 * exist yet.
 */

import { Box, Text } from "ink";
import type React from "react";
import { formatThreatModelSource } from "../../copilot/threat-model-loader.js";
import type { ShellState } from "../state.js";
import { tokens } from "../tokens.js";

const LABEL: Record<string, string> = {
  "threat-dfd": "data flow diagram",
  "threat-stride": "STRIDE × element matrix",
  "threat-stories": "attacker stories",
  "threat-scope": "scope & criticality",
  "threat-summary": "threat summary",
};

interface ThreatPlaceholderProps {
  shell: ShellState;
}

export function ThreatPlaceholder({ shell }: ThreatPlaceholderProps): React.ReactElement {
  const label = LABEL[shell.shellView ?? ""] ?? shell.shellView;
  const tm = shell.threatModel;

  return (
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <Text>
        {tokens.muted("\u25C2 back   ")}
        {tokens.strong(label)}
        {tokens.muted("   \u2502   ")}
        {tm ? (
          <>
            {tokens.value(`${tm.threats.length} threats`)}
            {tokens.muted("  \u00B7  ")}
            {tokens.value(`${tm.dfd.elements.length} elements`)}
          </>
        ) : (
          tokens.warn("no threat model loaded")
        )}
      </Text>

      {shell.threatModelSource ? (
        <Box marginTop={1}>
          <Text>
            {tokens.hint(
              formatThreatModelSource({
                sourcePath: shell.threatModelSource.path,
                mtimeMs: shell.threatModelSource.mtimeMs,
              }),
            )}
          </Text>
        </Box>
      ) : null}

      <Box marginTop={1}>
        <Text>
          {tokens.muted(
            "\u2014 view rendering lands in a subsequent Phase C commit. Press 1..5 to cycle.",
          )}
        </Text>
      </Box>
    </Box>
  );
}

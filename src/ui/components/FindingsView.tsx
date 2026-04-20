/**
 * Findings view — compact table of all completed triage results.
 *
 * Shown as a tab during the running phase. Updates live as results arrive.
 *
 *  #   Verdict          Confidence  Rule                   File
 *  1   ✗ TRUE POSITIVE   92%        sql-injection          src/api/users.ts:42
 *  2   ✓ false positive   78%        timing-attack          src/auth/login.ts:78
 *  3   ⚠ needs review     65%        weak-hash              src/utils/crypto.ts:15
 */

import { Box, Text } from "ink";
import type React from "react";
import { colorVerdict } from "../format.js";
import { icons } from "../icons.js";
import type { ResultLine } from "../state.js";
import { tokens } from "../tokens.js";

interface FindingsViewProps {
  results: ResultLine[];
}

export function FindingsView({ results }: FindingsViewProps): React.ReactElement {
  const triageResults = results.filter((r) => r.kind === "triage" && r.verdict);

  if (triageResults.length === 0) {
    return (
      <Box paddingLeft={2} marginTop={1}>
        <Text>{tokens.muted("No findings triaged yet...")}</Text>
      </Box>
    );
  }

  return (
    <Box flexDirection="column" paddingLeft={2} marginTop={1}>
      {/* Header */}
      <Text>
        {tokens.muted(pad("#", 4))}
        {tokens.muted(pad("Verdict", 20))}
        {tokens.muted(pad("Conf", 7))}
        {tokens.muted(pad("Cost", 8))}
        {tokens.muted("Fingerprint")}
      </Text>

      {/* Rows */}
      {triageResults.map((r) => {
        const idx = pad(String(r.index), 4);
        const verdict = r.verdict ? colorVerdict(r.verdict) : tokens.muted("—");
        const conf = r.confidence != null
          ? `${(r.confidence * 100).toFixed(0)}%`
          : "—";
        const cost = r.costUsd != null
          ? `$${r.costUsd.toFixed(3)}`
          : "—";
        const fp = tokens.muted(r.fingerprint.slice(0, 12));

        return (
          <Text key={r.fingerprint}>
            {tokens.muted(idx)}
            {pad(verdict, 20)}
            {pad(conf, 7)}
            {pad(cost, 8)}
            {fp}
          </Text>
        );
      })}

      {/* Summary line */}
      <Text>{""}</Text>
      <Text>
        {tokens.muted(`${triageResults.length} of ${results[0]?.total ?? "?"} triaged`)}
        {"  "}
        {tokens.danger(`${icons.error} ${triageResults.filter((r) => r.verdict === "tp").length} tp`)}
        {"  "}
        {tokens.success(`${icons.success} ${triageResults.filter((r) => r.verdict === "fp").length} fp`)}
        {"  "}
        {tokens.warn(`${icons.warning} ${triageResults.filter((r) => r.verdict === "needs_review").length} review`)}
      </Text>
    </Box>
  );
}

function pad(text: string, width: number): string {
  // Strip ANSI to measure visible length, then pad
  const visible = text.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "");
  const padding = Math.max(0, width - visible.length);
  return text + " ".repeat(padding);
}

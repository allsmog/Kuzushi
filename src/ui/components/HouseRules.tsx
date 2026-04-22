/**
 * HouseRules — per-module nudge text rendered as a read-only bordered block.
 *
 * Part of D6 (Ink UI v2 screen 06). Shows the contents of
 * `.kuzushi/house-rules/<moduleId>.md` when present, or an "empty" placeholder
 * with the char limit the v2 design calls out (600 chars). Editing is a
 * follow-up: for now, the operator edits the file directly; the shell picks
 * the change up on the next `/use`.
 */

import { Box, Text } from "ink";
import type React from "react";
import { SPACING, tokens } from "../tokens.js";

const MAX_CHARS = 600;
const WIDTH = 72;

interface HouseRulesProps {
  text?: string;
  path?: string;
}

export function HouseRules({ text, path }: HouseRulesProps): React.ReactElement {
  const count = text ? text.length : 0;
  const lines = text ? wrap(text, WIDTH - 4) : ["(empty — create the file to nudge this module)"];
  const bar = "\u2500".repeat(WIDTH);

  return (
    <Box flexDirection="column">
      <Text>
        {tokens.label("house rules")}
        {"  "}
        {tokens.hint("(optional · nudge this module about your repo)")}
      </Text>
      <Box marginTop={SPACING.sm} flexDirection="column">
        <Text>{tokens.muted(`   \u256D${bar}\u256E`)}</Text>
        {lines.map((line, i) => (
          <Text key={`${i}-${line.slice(0, 6)}`}>
            {tokens.muted("   \u2502 ")}
            {text ? tokens.value(line.padEnd(WIDTH - 3)) : tokens.muted(line.padEnd(WIDTH - 3))}
            {tokens.muted("\u2502")}
          </Text>
        ))}
        <Text>{tokens.muted(`   \u2570${bar}\u256F`)}</Text>
      </Box>
      <Box marginTop={SPACING.sm}>
        <Text>
          {tokens.muted(`   ${count} / ${MAX_CHARS} chars`)}
          {path ? tokens.muted(` · saved to ${relativeFrom(path)}`) : null}
        </Text>
      </Box>
    </Box>
  );
}

function wrap(text: string, width: number): string[] {
  const lines: string[] = [];
  for (const paragraph of text.split(/\n/)) {
    if (paragraph.length === 0) {
      lines.push("");
      continue;
    }
    const words = paragraph.split(/\s+/);
    let current = "";
    for (const word of words) {
      const next = current.length === 0 ? word : `${current} ${word}`;
      if (next.length > width) {
        if (current) lines.push(current);
        current = word;
      } else {
        current = next;
      }
    }
    if (current) lines.push(current);
  }
  return lines.length > 0 ? lines : [""];
}

function relativeFrom(abs: string): string {
  // Trim the home-dir prefix so the path stays short on normal terminals.
  const home = process.env["HOME"] ?? "";
  if (home && abs.startsWith(home)) {
    return `~${abs.slice(home.length)}`;
  }
  return abs;
}

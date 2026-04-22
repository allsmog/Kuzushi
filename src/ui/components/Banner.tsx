/**
 * Kuzushi startup banner — ASCII logo above the title.
 * Reads pre-generated ANSI-colored logo from assets/ascii/logo-color.txt.
 */

import { spawn } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Box, Static, Text } from "ink";
import React from "react";
import { SPACING, tokens } from "../tokens.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const assetsRoot = path.resolve(__dirname, "..", "..", "..", "assets");

function loadLogo(): string[] {
  try {
    const logoPath = path.join(assetsRoot, "ascii", "logo-color.txt");
    return readFileSync(logoPath, "utf-8").split("\n");
  } catch {
    return [];
  }
}

function playStartupSound(): void {
  try {
    const soundsDir = path.join(assetsRoot, "sounds");
    const files = readdirSync(soundsDir).filter((f) => f.endsWith(".wav"));
    if (files.length === 0) return;
    const pick = files[Math.floor(Math.random() * files.length)];
    const filePath = path.join(soundsDir, pick);

    const cmd =
      process.platform === "darwin" ? "afplay" : process.platform === "linux" ? "aplay" : null;
    if (!cmd) return;

    const child = spawn(cmd, [filePath], { stdio: "ignore", detached: true });
    child.unref();
  } catch {
    // Best-effort
  }
}

let soundPlayed = false;

export const Banner = React.memo(_Banner);

function _Banner(): React.ReactElement {
  const logoLines = loadLogo();

  if (!soundPlayed) {
    soundPlayed = true;
    playStartupSound();
  }

  return (
    <Static items={["banner"]}>
      {() => (
        <Box key="banner" flexDirection="column">
          <Text>{""}</Text>
          <Box flexDirection="row">
            <Box flexDirection="column">
              {logoLines.map((line, i) => (
                <Text key={`logo-${i}`}>{line}</Text>
              ))}
            </Box>
            <Box flexDirection="column" justifyContent="center" marginLeft={SPACING.md}>
              <Text>{""}</Text>
              <Text>{""}</Text>
              <Text>{""}</Text>
              <Text>{tokens.hint('"Bismillah"')}</Text>
            </Box>
          </Box>
          <Text>{""}</Text>
          <Box flexDirection="column" paddingLeft={SPACING.lg}>
            <Text>
              {tokens.strong(
                "\u2588\u2588\u2557  \u2588\u2588\u2557\u2588\u2588\u2557   \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557   \u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2557  \u2588\u2588\u2557\u2588\u2588\u2557",
              )}
            </Text>
            <Text>
              {tokens.strong(
                "\u2588\u2588\u2551 \u2588\u2588\u2554\u255D\u2588\u2588\u2551   \u2588\u2588\u2551\u255A\u2550\u2550\u2550\u2588\u2588\u2588\u2554\u255D\u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2550\u2550\u255D\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2551",
              )}
            </Text>
            <Text>
              {tokens.strong(
                "\u2588\u2588\u2588\u2588\u2588\u2554\u255D \u2588\u2588\u2551   \u2588\u2588\u2551  \u2588\u2588\u2588\u2554\u255D \u2588\u2588\u2551   \u2588\u2588\u2551\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551",
              )}
            </Text>
            <Text>
              {tokens.strong(
                "\u2588\u2588\u2554\u2550\u2588\u2588\u2557 \u2588\u2588\u2551   \u2588\u2588\u2551 \u2588\u2588\u2588\u2554\u255D  \u2588\u2588\u2551   \u2588\u2588\u2551\u255A\u2550\u2550\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551\u2588\u2588\u2551",
              )}
            </Text>
            <Text>
              {tokens.strong(
                "\u2588\u2588\u2551  \u2588\u2588\u2557\u255A\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255D\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2557\u255A\u2588\u2588\u2588\u2588\u2588\u2588\u2554\u255D\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2551\u2588\u2588\u2551  \u2588\u2588\u2551\u2588\u2588\u2551",
              )}
            </Text>
            <Text>
              {tokens.strong(
                "\u255A\u2550\u255D  \u255A\u2550\u255D \u255A\u2550\u2550\u2550\u2550\u2550\u255D \u255A\u2550\u2550\u2550\u2550\u2550\u2550\u255D \u255A\u2550\u2550\u2550\u2550\u2550\u255D \u255A\u2550\u2550\u2550\u2550\u2550\u2550\u255D\u255A\u2550\u255D  \u255A\u2550\u255D\u255A\u2550\u255D",
              )}
            </Text>
          </Box>
          <Text>{""}</Text>
          <Box paddingLeft={SPACING.lg}>
            <Text>
              {tokens.strong("\u5D29\u3057 ")} {tokens.muted("\u2014 Agentic SAST Orchestration")}
            </Text>
          </Box>
          <Text>{""}</Text>
        </Box>
      )}
    </Static>
  );
}

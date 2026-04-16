/**
 * Kuzushi startup banner — ASCII logo above the title.
 * Reads pre-generated ANSI-colored logo from assets/ascii/logo-color.txt.
 */

import { spawn } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import chalk from "chalk";
import { Box, Static, Text } from "ink";
import type React from "react";

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

export function Banner(): React.ReactElement {
  const rb = chalk.white.bold;
  const dim = chalk.dim;
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
            <Box flexDirection="column" justifyContent="center" marginLeft={2}>
              <Text>{""}</Text>
              <Text>{""}</Text>
              <Text>{""}</Text>
              <Text>{chalk.italic.dim('"Bismillah"')}</Text>
            </Box>
          </Box>
          <Text>{""}</Text>
          <Text>{rb("   ██╗  ██╗██╗   ██╗███████╗██╗   ██╗███████╗██╗  ██╗██╗")}</Text>
          <Text>{rb("   ██║ ██╔╝██║   ██║╚══███╔╝██║   ██║██╔════╝██║  ██║██║")}</Text>
          <Text>{rb("   █████╔╝ ██║   ██║  ███╔╝ ██║   ██║███████╗███████║██║")}</Text>
          <Text>{rb("   ██╔═██╗ ██║   ██║ ███╔╝  ██║   ██║╚════██║██╔══██║██║")}</Text>
          <Text>{rb("   ██║  ██╗╚██████╔╝███████╗╚██████╔╝███████║██║  ██║██║")}</Text>
          <Text>{rb("   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝")}</Text>
          <Text>{""}</Text>
          <Text>
            {chalk.white("   崩し ")} {dim("— Agentic SAST Orchestration")}
          </Text>
          <Text>{""}</Text>
        </Box>
      )}
    </Static>
  );
}

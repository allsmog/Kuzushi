#!/usr/bin/env npx tsx
/**
 * Mock TUI playthrough — boots the Ink shell with seeded `UIState` so a
 * developer can visually test every shell view without running scans,
 * LLMs, or builtin modules.
 *
 * Usage:
 *   npx tsx scripts/mock-tui.ts                   # list scenarios
 *   npx tsx scripts/mock-tui.ts --list            # list scenarios
 *   npx tsx scripts/mock-tui.ts <scenario-id>     # boot scenario
 *   npx tsx scripts/mock-tui.ts <id> --playback   # opt-in dynamic playback
 *
 * Or via the npm script:
 *   npm run mock-tui -- findings-many
 */
import { listScenarios, mountMockShell, SCENARIOS } from "../src/copilot/mock-tui/index.js";
// Import scenarios for their side-effect registration. The barrel module
// is created in Step 3 — until then this is a no-op import.
import "../src/copilot/mock-tui/scenarios/index.js";

const args = process.argv.slice(2);
const wantsList = args.includes("--list") || args.includes("-l") || args.length === 0;
const playback = args.includes("--playback");
const scenarioId = args.find((arg) => !arg.startsWith("-"));

if (wantsList && !scenarioId) {
  printScenarioList();
  process.exit(0);
}

if (!scenarioId) {
  console.error("Usage: npx tsx scripts/mock-tui.ts <scenario-id> [--playback]");
  process.exit(1);
}

const scenario = SCENARIOS[scenarioId];
if (!scenario) {
  console.error(`mock-tui: unknown scenario "${scenarioId}"`);
  console.error("");
  printScenarioList();
  process.exit(1);
}

const { store, cleanup } = await mountMockShell(scenario.seed());

let stopPlayback: (() => void) | undefined;
if (playback && scenario.playback) {
  stopPlayback = scenario.playback(store);
}

let exiting = false;
const onSignal = async (): Promise<void> => {
  if (exiting) return;
  exiting = true;
  if (stopPlayback) {
    try {
      stopPlayback();
    } catch {
      /* best-effort */
    }
  }
  await cleanup();
  process.exit(0);
};

process.once("SIGINT", () => {
  void onSignal();
});
process.once("SIGTERM", () => {
  void onSignal();
});

function printScenarioList(): void {
  const scenarios = listScenarios();
  if (scenarios.length === 0) {
    console.log("(no scenarios registered yet)");
    return;
  }
  console.log("Available mock-tui scenarios:");
  for (const s of scenarios) {
    const playbackTag = s.playback ? " [playback]" : "";
    console.log(`  ${s.id.padEnd(22)} ${s.description}${playbackTag}`);
  }
  console.log("");
  console.log("Run with:  npm run mock-tui -- <id>");
  console.log("           npx tsx scripts/mock-tui.ts <id> [--playback]");
}

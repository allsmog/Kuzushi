import { type SpawnOptions, spawn } from "node:child_process";
import { readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "./config.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_SOUNDS_DIR = path.resolve(__dirname, "..", "assets", "sounds");

type StartupSoundSpawn = (
  command: string,
  args: string[],
  options: SpawnOptions,
) => { unref(): void };

export interface StartupSoundOptions {
  enabled?: boolean;
  soundsDir?: string;
  platform?: NodeJS.Platform;
  random?: () => number;
  spawnCommand?: StartupSoundSpawn;
}

export function startupSoundCommand(platform: NodeJS.Platform = process.platform): string | null {
  if (platform === "darwin") return "afplay";
  if (platform === "linux") return "aplay";
  return null;
}

export function playStartupSound(options: StartupSoundOptions = {}): void {
  if (options.enabled !== true) return;

  try {
    const soundsDir = options.soundsDir ?? DEFAULT_SOUNDS_DIR;
    const files = readdirSync(soundsDir).filter((f) => f.endsWith(".wav"));
    if (files.length === 0) return;

    const random = options.random ?? Math.random;
    const pick = files[Math.floor(random() * files.length)] ?? files[0];
    const filePath = path.join(soundsDir, pick);
    const cmd = startupSoundCommand(options.platform);
    if (!cmd) return;

    const spawnCommand = options.spawnCommand ?? spawn;
    const child = spawnCommand(cmd, [filePath], { stdio: "ignore", detached: true });
    child.unref();
  } catch {
    // Best-effort cosmetic feature. Missing assets, audio binaries, or
    // headless environments should never affect Kuzushi startup.
  }
}

export function playGlobalStartupSound(): void {
  try {
    playStartupSound({ enabled: loadConfig().startupSound === true });
  } catch {
    // If config loading fails unexpectedly, keep startup quiet and non-fatal.
  }
}

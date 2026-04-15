import os from "node:os";
import path from "node:path";
import { discoverConfigFile } from "../config-io.js";

export const CONFIG_DIR = path.join(os.homedir(), ".kuzushi");
export const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");
const PROJECT_CONFIG_DIR = ".kuzushi";
const CONFIG_BASENAME = "config";

export function configPath(): string {
  const discovered = discoverConfigFile(CONFIG_DIR, CONFIG_BASENAME);
  if (discovered) {
    return discovered.path;
  }
  return CONFIG_PATH;
}

export function projectConfigPath(repoRoot: string): string {
  const dir = path.join(repoRoot, PROJECT_CONFIG_DIR);
  const discovered = discoverConfigFile(dir, CONFIG_BASENAME);
  if (discovered) {
    return discovered.path;
  }
  return path.join(dir, `${CONFIG_BASENAME}.json`);
}

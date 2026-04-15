/**
 * Interactive setup/confirmation flow.
 *
 * - First-time users (no config): full setup wizard
 * - Returning users (fresh scan): config confirmation prompt
 * - Resume users: skip entirely (go straight to pipeline)
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { WizardResult } from "./components/SetupWizard.js";
import type { ConfigConfirmData } from "./components/ConfigConfirm.js";
import { emitOutputNotice } from "./output.js";
import type { UIStore } from "./state.js";

export type SetupOutcome =
  | { action: "proceed"; preset?: string; model?: string }
  | { action: "cancel" };

/**
 * Detect whether this is a first-time run (no config file exists).
 */
export function isFirstRun(repoRoot: string): boolean {
  const projectConfig = path.join(repoRoot, ".kuzushi", "config.json");
  const projectYaml = path.join(repoRoot, ".kuzushi", "config.yaml");
  const projectYml = path.join(repoRoot, ".kuzushi", "config.yml");
  const home = process.env["HOME"] ?? process.env["USERPROFILE"] ?? "";
  const globalConfig = path.join(home, ".kuzushi", "config.json");
  const globalYaml = path.join(home, ".kuzushi", "config.yaml");
  const globalYml = path.join(home, ".kuzushi", "config.yml");

  return ![projectConfig, projectYaml, projectYml, globalConfig, globalYaml, globalYml]
    .some((p) => existsSync(p));
}

/**
 * Run the setup wizard (first-time users).
 */
export async function runSetupWizard(
  store: UIStore | undefined,
  repoName: string,
  repoRoot: string,
): Promise<SetupOutcome> {
  if (!process.stdout.isTTY) {
    return { action: "proceed" };
  }

  if (!store) {
    return { action: "proceed" };
  }

  return new Promise<SetupOutcome>((resolve) => {
    store.setPreflight({
      kind: "wizard",
      repoName,
      repoRoot,
      onComplete: (result: WizardResult) => {
        store.setPreflight(null);
        if (result.saveLocation && result.saveLocation !== "none") {
          saveWizardConfig(result, repoRoot, store);
        }
        resolve({
          action: "proceed",
          preset: result.preset,
          model: result.model,
        });
      },
      onCancel: () => {
        store.setPreflight(null);
        resolve({ action: "cancel" });
      },
    });
  });
}

/**
 * Show config confirmation (returning users, fresh scans only).
 */
export async function runConfigConfirmation(
  store: UIStore | undefined,
  config: ConfigConfirmData,
  repoName: string,
  repoRoot: string,
): Promise<SetupOutcome> {
  if (!process.stdout.isTTY) {
    return { action: "proceed" };
  }

  if (!store) {
    return { action: "proceed" };
  }

  return new Promise<SetupOutcome>((resolve) => {
    store.setPreflight({
      kind: "confirm",
      repoName,
      repoRoot,
      config,
      onProceed: () => {
        store.setPreflight(null);
        resolve({ action: "proceed" });
      },
      onEdit: () => {
        store.setPreflight(null);
        runSetupWizard(store, repoName, repoRoot).then(resolve);
      },
      onQuit: () => {
        store.setPreflight(null);
        resolve({ action: "cancel" });
      },
    });
  });
}

/**
 * Save wizard results to config file.
 */
function saveWizardConfig(result: WizardResult, repoRoot: string, store?: UIStore): void {
  const config: Record<string, unknown> = {};

  // Map preset to config fields
  if (result.preset) {
    config["preset"] = result.preset;
  }
  if (result.model) {
    config["model"] = result.model;
  }
  if (result.verify) {
    config["verify"] = true;
  }
  if (result.pocHarness) {
    config["pocHarness"] = true;
  }
  if (result.severity) {
    config["severity"] = result.severity;
  }

  const targetDir = result.saveLocation === "project"
    ? path.join(repoRoot, ".kuzushi")
    : path.join(process.env["HOME"] ?? process.env["USERPROFILE"] ?? ".", ".kuzushi");

  if (!existsSync(targetDir)) {
    mkdirSync(targetDir, { recursive: true });
  }

  const targetPath = path.join(targetDir, "config.json");
  writeFileSync(targetPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
  store?.addNotice({
    level: "success",
    message: "Config saved",
    detail: targetPath,
    source: "setup",
  });
  if (!store) {
    emitOutputNotice({
      level: "success",
      message: "Config saved",
      detail: targetPath,
      source: "setup",
    });
  }
}

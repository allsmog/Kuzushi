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
export async function runSetupWizard(repoName: string, repoRoot: string): Promise<SetupOutcome> {
  if (!process.stdout.isTTY) {
    return { action: "proceed" };
  }

  const { render } = await import("ink");
  const { createElement } = await import("react");
  const { SetupWizard } = await import("./components/SetupWizard.js");

  return new Promise<SetupOutcome>((resolve) => {
    const instance = render(
      createElement(SetupWizard, {
        repoName,
        onComplete: (result: WizardResult) => {
          instance.unmount();
          // Save config if requested
          if (result.saveLocation && result.saveLocation !== "none") {
            saveWizardConfig(result, repoRoot);
          }
          resolve({
            action: "proceed",
            preset: result.preset,
            model: result.model,
          });
        },
        onCancel: () => {
          instance.unmount();
          resolve({ action: "cancel" });
        },
      }),
    );
  });
}

/**
 * Show config confirmation (returning users, fresh scans only).
 */
export async function runConfigConfirmation(
  config: ConfigConfirmData,
  repoName: string,
): Promise<SetupOutcome> {
  if (!process.stdout.isTTY) {
    return { action: "proceed" };
  }

  const { render } = await import("ink");
  const { createElement } = await import("react");
  const { ConfigConfirm } = await import("./components/ConfigConfirm.js");

  return new Promise<SetupOutcome>((resolve) => {
    let instance: ReturnType<typeof render>;
    instance = render(
      createElement(ConfigConfirm, {
        config,
        repoName,
        onProceed: () => {
          instance.unmount();
          resolve({ action: "proceed" });
        },
        onEdit: () => {
          instance.unmount();
          // Re-run as wizard
          runSetupWizard(repoName, ".").then(resolve);
        },
        onQuit: () => {
          instance.unmount();
          resolve({ action: "cancel" });
        },
      }),
    );
  });
}

/**
 * Save wizard results to config file.
 */
function saveWizardConfig(result: WizardResult, repoRoot: string): void {
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
  console.log(`  ${chalk.dim("Config saved to")} ${targetPath}`);
}

// Lazy import for chalk in saveWizardConfig
import chalk from "chalk";

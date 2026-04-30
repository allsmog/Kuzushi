/**
 * Interactive setup/confirmation flow.
 *
 * - First-time users (no config): full setup wizard
 * - Returning users (fresh scan): config confirmation prompt
 * - Resume users: skip entirely (go straight to pipeline)
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { ThreatModelDocument } from "../agents/tasks/threat-modeling/types.js";
import type { ConfigPatchEntry } from "../config.js";
import { applyConfigPatch, configPath, loadConfig, resolveAmbientOauthToken } from "../config.js";
import { saveOperatorScanContext } from "../operator-context.js";
import { savePersistentThreatModel } from "../threat-model-renderer.js";
import type { OperatorScanContext } from "../types.js";
import { emitOutputNotice } from "./output.js";
import type { ConfigConfirmData, CredentialChoice, WizardResult } from "./preflight-types.js";
import type { UIMode, UIStore } from "./state.js";

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

  return ![projectConfig, projectYaml, projectYml, globalConfig, globalYaml, globalYml].some((p) =>
    existsSync(p),
  );
}

/**
 * Run the setup wizard (first-time users).
 */
export async function runSetupWizard(
  store: UIStore | undefined,
  repoName: string,
  repoRoot: string,
  returnMode: UIMode = "running",
): Promise<SetupOutcome> {
  if (!process.stdout.isTTY) {
    return { action: "proceed" };
  }

  if (!store) {
    return { action: "proceed" };
  }

  return new Promise<SetupOutcome>((resolve) => {
    store.setPreflight(
      {
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
      },
      returnMode,
    );
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
  returnMode: UIMode = "running",
): Promise<SetupOutcome> {
  if (!process.stdout.isTTY) {
    return { action: "proceed" };
  }

  if (!store) {
    return { action: "proceed" };
  }

  return new Promise<SetupOutcome>((resolve) => {
    store.setPreflight(
      {
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
          runSetupWizard(store, repoName, repoRoot, returnMode).then(resolve);
        },
        onQuit: () => {
          store.setPreflight(null);
          resolve({ action: "cancel" });
        },
      },
      returnMode,
    );
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

  const targetDir =
    result.saveLocation === "project"
      ? path.join(repoRoot, ".kuzushi")
      : path.join(process.env["HOME"] ?? process.env["USERPROFILE"] ?? ".", ".kuzushi");

  if (!existsSync(targetDir)) {
    mkdirSync(targetDir, { recursive: true });
  }

  const targetPath = path.join(targetDir, "config.json");
  writeFileSync(targetPath, `${JSON.stringify(config, null, 2)}\n`, "utf-8");
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

/**
 * Check whether valid Anthropic credentials are available for the Claude backend.
 *
 * Returns `true` when at least one credential source is present:
 *   - explicit `apiKey` or `authToken` in config
 *   - `ANTHROPIC_API_KEY` environment variable
 *   - `ANTHROPIC_AUTH_TOKEN` environment variable
 *   - `ANTHROPIC_OAUTH_TOKEN` environment variable
 */
export function hasAnthropicCredentials(configApiKey?: string, configAuthToken?: string): boolean {
  if (configApiKey) return true;
  if (configAuthToken) return true;
  if (process.env["ANTHROPIC_API_KEY"]) return true;
  if (process.env["ANTHROPIC_AUTH_TOKEN"]) return true;
  if (process.env["ANTHROPIC_OAUTH_TOKEN"]) return true;
  // File-based ambient OAuth (Claude Code remote sandbox, local install).
  if (resolveAmbientOauthToken({})) return true;
  return false;
}

/**
 * Check whether *any* provider has credentials present, via env vars.
 *
 * Matches pi-ai's env resolution so we don't prompt when the operator
 * already exported ANTHROPIC_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY /
 * etc., or pointed at a local Ollama endpoint.
 */
export function hasAnyProviderCredentials(): boolean {
  const envKeys = [
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_OAUTH_TOKEN",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "MISTRAL_API_KEY",
    "GROQ_API_KEY",
    "CEREBRAS_API_KEY",
    "XAI_API_KEY",
    "OPENROUTER_API_KEY",
    "OLLAMA_BASE_URL",
  ];
  if (envKeys.some((k) => Boolean(process.env[k]))) return true;
  if (resolveAmbientOauthToken({})) return true;
  return false;
}

export type CredentialOutcome =
  | { action: "proceed"; choice: CredentialChoice }
  | { action: "cancel" };

/**
 * Show interactive credential prompt (TTY only).
 * Returns the user's chosen auth method so the caller can apply it to config/env.
 */
export async function runCredentialPrompt(
  store: UIStore | undefined,
  returnMode: UIMode = "running",
): Promise<CredentialOutcome> {
  if (!process.stdout.isTTY || !store) {
    return { action: "cancel" };
  }

  return new Promise<CredentialOutcome>((resolve) => {
    store.setPreflight(
      {
        kind: "credentials",
        onComplete: (choice: CredentialChoice) => {
          store.setPreflight(null);
          resolve({ action: "proceed", choice });
        },
        onCancel: () => {
          store.setPreflight(null);
          resolve({ action: "cancel" });
        },
      },
      returnMode,
    );
  });
}

/**
 * Stdin-based credential prompt for the readline (non-Ink) shell.
 *
 * Asks the user to choose an auth method, paste a token (echoed as `*`), and
 * (for API keys only) opt into persisting it to `~/.kuzushi/config.json`.
 * Returns `{ action: "cancel" }` on EOF or empty selection so the caller can
 * surface the same disabled-copilot message as the Ink path.
 */
export async function runReadlineCredentialPrompt(): Promise<CredentialOutcome> {
  const readline = await import("node:readline");

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
    terminal: true,
  });

  const ask = (question: string): Promise<string | null> =>
    new Promise((resolve) => {
      rl.question(question, (answer) => resolve(answer));
      rl.once("close", () => resolve(null));
    });

  const askMasked = (question: string): Promise<string | null> => {
    const out = process.stderr as NodeJS.WriteStream & { _writeToOutput?: (s: string) => void };
    process.stderr.write(question);
    let buffer = "";
    return new Promise((resolve) => {
      const onData = (chunk: Buffer): void => {
        const str = chunk.toString("utf-8");
        for (const ch of str) {
          if (ch === "\n" || ch === "\r") {
            process.stdin.removeListener("data", onData);
            try {
              process.stdin.setRawMode?.(false);
            } catch {
              // ignore — not all environments support raw mode
            }
            process.stderr.write("\n");
            resolve(buffer);
            return;
          }
          if (ch === "\u0003") {
            // Ctrl-C
            process.stdin.removeListener("data", onData);
            try {
              process.stdin.setRawMode?.(false);
            } catch {
              // ignore
            }
            process.stderr.write("\n");
            resolve(null);
            return;
          }
          if (ch === "\u007f" || ch === "\b") {
            buffer = buffer.slice(0, -1);
            continue;
          }
          buffer += ch;
          process.stderr.write("*");
        }
      };
      try {
        process.stdin.setRawMode?.(true);
      } catch {
        // ignore
      }
      process.stdin.resume();
      process.stdin.on("data", onData);
      // Touch out._writeToOutput to silence biome unused-var on platforms
      // without raw mode; the variable is only here for typing.
      void out;
    });
  };

  try {
    // Readline fallback is kept minimal — defaults to Anthropic because it's
    // the most common path and the user can always use the full Ink TTY
    // flow for other providers.
    const choice = await ask(
      "Authenticate — [c] Inherit Claude (parent session)  [1] Anthropic API key  [i] use env vars  [Enter] Skip: ",
    );
    if (choice === null) return { action: "cancel" };
    const trimmedChoice = choice.trim().toLowerCase();
    if (trimmedChoice === "" || trimmedChoice === "q") return { action: "cancel" };
    if (trimmedChoice === "c" || trimmedChoice === "inherited-claude") {
      return { action: "proceed", choice: { kind: "inherited", providerId: "inherited-claude" } };
    }
    if (trimmedChoice === "i" || trimmedChoice === "inherited") {
      return { action: "proceed", choice: { kind: "inherited", providerId: "anthropic" } };
    }

    if (trimmedChoice === "1") {
      const value = await askMasked("Paste ANTHROPIC_API_KEY (input hidden): ");
      if (value === null) return { action: "cancel" };
      const trimmed = value.trim();
      if (trimmed.length === 0) return { action: "cancel" };

      const baseUrlRaw = await ask("Custom ANTHROPIC_BASE_URL? (blank for default): ");
      if (baseUrlRaw === null) return { action: "cancel" };
      const baseUrl = baseUrlRaw.trim() || undefined;

      const save = await ask(
        "Save to ./.kuzushi/credentials.json so future runs pick it up? [Y/n]: ",
      );
      if (save === null) return { action: "cancel" };
      const persist = save.trim().toLowerCase() !== "n" && save.trim().toLowerCase() !== "no";

      return {
        action: "proceed",
        choice: { kind: "api-key", providerId: "anthropic", value: trimmed, baseUrl, persist },
      };
    }

    return { action: "cancel" };
  } finally {
    rl.close();
  }
}

// ── Context Intake ──

export type ContextIntakeOutcome =
  | { action: "proceed"; context: OperatorScanContext }
  | { action: "skip" }
  | { action: "cancel" };

/**
 * Show the operator context intake editor (TTY only).
 */
export async function runContextIntake(
  store: UIStore | undefined,
  initialContext: OperatorScanContext,
  repoName: string,
  repoRoot: string,
  returnMode: UIMode = "running",
): Promise<ContextIntakeOutcome> {
  if (!process.stdout.isTTY || !store) {
    return { action: "skip" };
  }

  return new Promise<ContextIntakeOutcome>((resolve) => {
    store.setPreflight(
      {
        kind: "context-intake",
        repoName,
        repoRoot,
        initialContext,
        onComplete: (context: OperatorScanContext) => {
          store.setPreflight(null);
          saveOperatorScanContext(repoRoot, context);
          store.addNotice({
            level: "success",
            message: "Operator context saved",
            detail: path.join(repoRoot, ".kuzushi", "scan-context.json"),
            source: "intake",
          });
          resolve({ action: "proceed", context });
        },
        onSkip: () => {
          store.setPreflight(null);
          resolve({ action: "skip" });
        },
        onCancel: () => {
          store.setPreflight(null);
          resolve({ action: "cancel" });
        },
      },
      returnMode,
    );
  });
}

// ── Threat Model Editor ──

export type ThreatModelEditorOutcome =
  | { action: "proceed"; threatModel: ThreatModelDocument }
  | { action: "skip" }
  | { action: "cancel" };

/**
 * Show the interactive threat model editor (TTY only).
 */
export async function runThreatModelEditor(
  store: UIStore | undefined,
  threatModel: ThreatModelDocument,
  repoName: string,
  repoRoot: string,
  returnMode: UIMode = "running",
): Promise<ThreatModelEditorOutcome> {
  if (!process.stdout.isTTY || !store) {
    return { action: "skip" };
  }

  return new Promise<ThreatModelEditorOutcome>((resolve) => {
    store.setPreflight(
      {
        kind: "threat-editor",
        repoName,
        repoRoot,
        threatModel,
        onComplete: (updated: ThreatModelDocument) => {
          store.setPreflight(null);
          savePersistentThreatModel(repoRoot, updated, true);
          store.addNotice({
            level: "success",
            message: "Threat model saved",
            detail: path.join(repoRoot, ".kuzushi", "threat-model.json"),
            source: "intake",
          });
          resolve({ action: "proceed", threatModel: updated });
        },
        onSkip: () => {
          store.setPreflight(null);
          resolve({ action: "skip" });
        },
        onCancel: () => {
          store.setPreflight(null);
          resolve({ action: "cancel" });
        },
      },
      returnMode,
    );
  });
}

// ── Config Editor ──

export type ConfigEditorOutcome =
  | { action: "saved"; changed: number; restartKeys: string[] }
  | { action: "cancelled" }
  | { action: "skipped" };

const CONFIG_RESTART_KEYS = new Set([
  "agentRuntimeBackend",
  "agentRuntimeConfig",
  "agentModel",
  "busBackend",
  "dbPath",
]);

/**
 * Show the interactive `/config` editor (TTY only). Persists changes to
 * `~/.kuzushi/config.json` via {@link applyConfigPatch} and resolves with a
 * summary the shell uses to acknowledge the action.
 */
export async function runConfigEditor(
  store: UIStore | undefined,
  focusKey?: string,
  returnMode: UIMode = "shell",
): Promise<ConfigEditorOutcome> {
  if (!process.stdout.isTTY || !store) {
    return { action: "skipped" };
  }

  const initialConfig = loadConfig();
  const cfgPath = configPath();

  return new Promise<ConfigEditorOutcome>((resolve) => {
    store.setPreflight(
      {
        kind: "config-editor",
        initialConfig,
        configPath: cfgPath,
        focusKey,
        onComplete: (patch: ConfigPatchEntry[]) => {
          store.setPreflight(null);
          if (patch.length === 0) {
            resolve({ action: "saved", changed: 0, restartKeys: [] });
            return;
          }
          try {
            applyConfigPatch(patch);
            const restartKeys = [
              ...new Set(
                patch.map((e) => e.path.split(".")[0]!).filter((k) => CONFIG_RESTART_KEYS.has(k)),
              ),
            ];
            store.addNotice({
              level: "success",
              message: `Config updated (${patch.length} key${patch.length === 1 ? "" : "s"})`,
              detail: cfgPath,
              source: "config",
            });
            resolve({ action: "saved", changed: patch.length, restartKeys });
          } catch (err) {
            store.addNotice({
              level: "error",
              message: "Failed to save config",
              detail: err instanceof Error ? err.message : String(err),
              source: "config",
            });
            resolve({ action: "cancelled" });
          }
        },
        onCancel: () => {
          store.setPreflight(null);
          resolve({ action: "cancelled" });
        },
      },
      returnMode,
    );
  });
}

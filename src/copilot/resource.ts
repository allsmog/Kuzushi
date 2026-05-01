/**
 * Resource scripts — replayable command sequences.
 *
 * Two formats:
 *
 *  1. YAML (preferred — `.kzrc.yaml` / `.kzrc.yml`):
 *     ```yaml
 *     workspace: acme-prod
 *     setg:
 *       MODEL: claude-opus-4-7
 *     commands:
 *       - use sast
 *       - set TARGET ./
 *       - run
 *     ```
 *
 *  2. Plain text (`.rc`): one command per line; lines starting with `#` are comments.
 *
 * Inspired by msfconsole's `resource` and `makerc` (lib/msf/ui/console/command_dispatcher/resource.rb).
 *
 * Embedded scripting (msf's `<ruby>...</ruby>`) is intentionally NOT supported —
 * we keep .kzrc files declarative-only. Hostile resource files can run arbitrary
 * tools, so callers should treat them as trusted input.
 */

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { toErrorMessage } from "../utils.js";
import type { CommandResult, Driver } from "./dispatcher/types.js";
export interface ResourceScript {
  workspace?: string;
  setg?: Record<string, string | number | boolean>;
  commands: string[];
}

const TEXT_RC = /\.rc$/i;

/** Parse a resource script from a string. Format inferred from path or content. */
export function parseResourceScript(content: string, filename?: string): ResourceScript {
  const isText = filename ? TEXT_RC.test(filename) : !looksLikeYaml(content);
  if (isText) {
    return { commands: parseTextRc(content) };
  }
  return parseYamlRc(content);
}

function looksLikeYaml(content: string): boolean {
  return /(^|\n)\s*(commands|setg|workspace)\s*:/.test(content);
}

function parseTextRc(content: string): string[] {
  return content
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
}

function parseYamlRc(content: string): ResourceScript {
  const parsed = parseYaml(content) as unknown;
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Resource file must be an object");
  }
  const obj = parsed as Record<string, unknown>;
  const commands = obj["commands"];
  if (!Array.isArray(commands)) {
    throw new Error("Resource file requires a `commands:` array");
  }
  if (!commands.every((c) => typeof c === "string")) {
    throw new Error("Every entry in `commands:` must be a string");
  }
  const result: ResourceScript = { commands };
  if (typeof obj["workspace"] === "string") result.workspace = obj["workspace"];
  if (obj["setg"] && typeof obj["setg"] === "object") {
    result.setg = obj["setg"] as Record<string, string | number | boolean>;
  }
  return result;
}

/** Resolve a resource path relative to cwd or known search dirs. */
export function resolveResourcePath(file: string, cwd: string, searchDirs: string[] = []): string {
  if (path.isAbsolute(file)) return file;
  const candidates = [path.resolve(cwd, file), ...searchDirs.map((d) => path.resolve(d, file))];
  return candidates[0] as string;
}

export interface RunResourceOptions {
  driver: Driver;
  /** Optional signal forwarded to each command. */
  signal?: AbortSignal;
  /** Stop on first error (default true). */
  stopOnError?: boolean;
}

export interface RunResourceResult {
  executed: number;
  errors: Array<{ command: string; error: string }>;
}

/** Execute every command in a script through the driver. */
export async function runResourceScript(
  script: ResourceScript,
  opts: RunResourceOptions,
): Promise<RunResourceResult> {
  const stopOnError = opts.stopOnError ?? true;
  const result: RunResourceResult = { executed: 0, errors: [] };

  // Apply setg first.
  if (script.setg) {
    for (const [key, value] of Object.entries(script.setg)) {
      const out = await opts.driver.handle(`setg ${key} ${String(value)}`, opts.signal);
      handleCommandResult(opts.driver, out);
    }
  }

  for (const raw of script.commands) {
    const command = raw.trim();
    if (command.length === 0 || command.startsWith("#")) continue;
    try {
      const out = await opts.driver.handle(command, opts.signal);
      handleCommandResult(opts.driver, out);
      result.executed++;
      if (out.exit) return result;
    } catch (err) {
      const msg = toErrorMessage(err);
      result.errors.push({ command, error: msg });
      opts.driver.print.error(`resource: ${command}: ${msg}`);
      if (stopOnError) return result;
    }
  }

  return result;
}

function handleCommandResult(driver: Driver, result: CommandResult): void {
  if (result.output) driver.print.line(result.output);
}

/** Load + execute a resource script from disk. */
export async function loadAndRunResource(
  file: string,
  opts: RunResourceOptions & { cwd: string },
): Promise<RunResourceResult> {
  const resolved = resolveResourcePath(file, opts.cwd);
  const content = await readFile(resolved, "utf8");
  const script = parseResourceScript(content, resolved);
  return runResourceScript(script, opts);
}

/** Save a resource script (YAML form). */
export async function saveResourceScript(file: string, script: ResourceScript): Promise<void> {
  const yaml = stringifyYaml(script, { lineWidth: 0 });
  await writeFile(file, yaml, "utf8");
}

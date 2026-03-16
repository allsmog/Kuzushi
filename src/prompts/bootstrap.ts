/**
 * Bootstrap file injection for system prompts.
 *
 * Reads workspace-level guidance files (e.g., triage guidelines,
 * security context) and injects them into the system prompt prefix
 * with configurable token budgets.
 */

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { sanitizeLight } from "./sanitize.js";

/** Configuration for bootstrap file loading. */
export interface BootstrapConfig {
  /** Paths relative to repo root. */
  files?: string[];
  /** Maximum characters per file. Default 20_000. */
  maxCharsPerFile?: number;
  /** Maximum total characters across all files. Default 100_000. */
  totalMaxChars?: number;
}

const DEFAULT_MAX_CHARS_PER_FILE = 20_000;
const DEFAULT_TOTAL_MAX_CHARS = 100_000;

/**
 * Load bootstrap context files and compose them into a string
 * suitable for injection into a system prompt prefix.
 *
 * Files are read in order, trimmed to per-file budget,
 * and the total is trimmed to the overall budget.
 * Missing files are silently skipped.
 *
 * @param repoRoot - Absolute path to the repository root
 * @param config - Bootstrap configuration
 * @returns Composed bootstrap context string, or empty string if no files loaded
 */
export function loadBootstrapContext(
  repoRoot: string,
  config: BootstrapConfig,
): string {
  if (!config.files || config.files.length === 0) {
    return "";
  }

  const maxPerFile = config.maxCharsPerFile ?? DEFAULT_MAX_CHARS_PER_FILE;
  const maxTotal = config.totalMaxChars ?? DEFAULT_TOTAL_MAX_CHARS;

  const sections: string[] = [];
  let totalChars = 0;

  for (const filePath of config.files) {
    const absPath = path.resolve(repoRoot, filePath);
    if (!existsSync(absPath)) {
      continue;
    }

    let content: string;
    try {
      content = sanitizeLight(readFileSync(absPath, "utf-8"));
    } catch {
      continue;
    }

    // Trim to per-file budget
    if (content.length > maxPerFile) {
      content = content.slice(0, maxPerFile) + `\n[... truncated, ${content.length - maxPerFile} chars omitted]`;
    }

    // Check total budget
    if (totalChars + content.length > maxTotal) {
      const remaining = maxTotal - totalChars;
      if (remaining > 100) {
        content = content.slice(0, remaining) + `\n[... truncated to fit total budget]`;
        sections.push(formatSection(filePath, content));
      }
      break;
    }

    sections.push(formatSection(filePath, content));
    totalChars += content.length;
  }

  if (sections.length === 0) {
    return "";
  }

  return [
    "## Project Context",
    "",
    "The following project-specific context has been loaded from workspace configuration files:",
    "",
    ...sections,
  ].join("\n");
}

function formatSection(filePath: string, content: string): string {
  return [
    `### ${filePath}`,
    "",
    content,
    "",
  ].join("\n");
}

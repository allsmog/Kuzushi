import { existsSync, mkdirSync, readdirSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { createLogger } from "../logger.js";
import type { GeneratedRule } from "./types.js";

const log = createLogger({ stage: "rule-persistence" });

const CUSTOM_RULES_DIR = ".kuzushi/custom-rules";

/**
 * Persist a generated Semgrep rule to .kuzushi/custom-rules/.
 * Only persists "semgrep" kind rules (grep patterns are not loadable by Semgrep).
 * Returns the file path if written, null if skipped.
 */
export function persistRule(repoRoot: string, rule: GeneratedRule): string | null {
  if (rule.kind !== "semgrep") return null;
  if (!rule.ruleContent.trim()) return null;

  const dir = path.join(repoRoot, CUSTOM_RULES_DIR);
  mkdirSync(dir, { recursive: true });

  const prefix = rule.sourceFinding.fingerprint.slice(0, 12);
  const vulnClass = rule.vulnClass.replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase();
  const filename = `${prefix}-${vulnClass}.yaml`;
  const filePath = path.join(dir, filename);

  writeFileSync(filePath, rule.ruleContent, "utf-8");
  log.info(`Persisted rule: ${filename}`);
  return filePath;
}

/**
 * Remove a persisted rule file (e.g., after validation failure).
 */
export function removeRule(filePath: string): void {
  try {
    unlinkSync(filePath);
  } catch {
    // File may already be gone
  }
}

/**
 * Returns the .kuzushi/custom-rules/ directory path if it exists and contains
 * .yaml files. Returns null otherwise. Used by Semgrep to auto-load custom rules.
 */
export function loadCustomRulesDir(repoRoot: string): string | null {
  const dir = path.join(repoRoot, CUSTOM_RULES_DIR);
  if (!existsSync(dir)) return null;

  try {
    const files = readdirSync(dir);
    const hasYaml = files.some((f) => f.endsWith(".yaml") || f.endsWith(".yml"));
    return hasYaml ? dir : null;
  } catch {
    return null;
  }
}

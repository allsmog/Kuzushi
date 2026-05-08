import { readFileSync } from "node:fs";
import type { KuzushiConfig } from "../types.js";
import { TRIAGE_TEMPLATE } from "./templates/triage.js";
import { VERIFY_UNIFIED_TEMPLATE } from "./templates/verify.js";

export interface ResolvedTemplates {
  triage: string;
  verify: string;
}

/**
 * Resolve prompt templates from config, falling back to built-in defaults.
 * Custom templates are loaded from disk and validated at load time.
 */
export function resolveTemplates(config: KuzushiConfig): ResolvedTemplates {
  const triage = config.triagePromptFile
    ? loadAndValidateTemplate(config.triagePromptFile, "triage")
    : TRIAGE_TEMPLATE;
  const verify = config.verifyPromptFile
    ? loadAndValidateTemplate(config.verifyPromptFile, "verify")
    : VERIFY_UNIFIED_TEMPLATE;
  return { triage, verify };
}

function loadAndValidateTemplate(filePath: string, label: string): string {
  let content: string;
  try {
    content = readFileSync(filePath, "utf-8");
  } catch (err) {
    throw new Error(
      `Failed to load custom ${label} template from "${filePath}": ${(err as Error).message}`,
    );
  }

  if (!content.trim()) {
    throw new Error(`Custom ${label} template at "${filePath}" is empty`);
  }

  return content;
}

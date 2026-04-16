/**
 * Language-specific prompt tuning — composition layer.
 *
 * Detection tasks call these functions to get prompt sections
 * tailored to the detected languages in the target repo.
 */

import type { RepoContext } from "../types.js";
import { getLanguageProfiles } from "./languages/index.js";
import type { FrameworkGuidance, LanguageFewShot, VulnClassContent } from "./languages/types.js";

// ---------------------------------------------------------------------------
// Task ID -> canonical vuln class mapping
// ---------------------------------------------------------------------------

const TASK_TO_VULN_CLASS: Record<string, string | string[]> = {
  // Detection tasks
  "command-injection": "command-injection",
  "ssrf-detection": "ssrf",
  "deserialization-detection": "deserialization",
  "xxe-detection": "xxe",
  "template-injection": "template-injection",
  "race-condition": "race-condition",
  "prototype-pollution": "prototype-pollution",
  "secrets-crypto-detect": "crypto-misuse",
  "code-config-detect": "security-misconfig",
  "nosql-injection": "nosql-injection",
  "auth-logic-detect": "auth-bypass",
  "graphql-security": "graphql",
  "supply-chain": "supply-chain",
  // Agentic scanner gets a merged view of all classes
  agentic: [
    "command-injection",
    "ssrf",
    "deserialization",
    "xxe",
    "template-injection",
    "auth-bypass",
    "sqli",
    "xss",
  ],
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface LanguageTuningOpts {
  /** The task ID requesting tuning */
  taskId: string;
  /** Repo context from context-gatherer */
  repoContext: RepoContext | undefined;
  /** Detected frameworks to filter framework guidance */
  frameworks?: string[];
}

/**
 * Generate a language-specific prompt section with sinks, safe patterns,
 * and framework guidance for a detection task.
 *
 * Returns empty string if no language profiles match.
 */
export function languageTuningModule(opts: LanguageTuningOpts): string {
  const entries = resolveEntries(opts);
  if (entries.length === 0) return "";

  const sections: string[] = ["## Language-Specific Guidance\n"];

  for (const { profile, content } of entries) {
    sections.push(`### ${profile.languageId}\n`);

    // Sinks
    if (content.sinks.length > 0) {
      sections.push("**Dangerous sinks:**");
      for (const s of content.sinks) {
        const shell =
          s.shellInvoking === true ? " [SHELL]" : s.shellInvoking === false ? " [NO-SHELL]" : "";
        sections.push(`- \`${s.api}\`${shell}: ${s.risk}`);
      }
      sections.push("");
    }

    // Safe patterns
    if (content.safePatterns.length > 0) {
      sections.push("**Safe patterns (do NOT flag):**");
      for (const sp of content.safePatterns) {
        sections.push(`- \`${sp.api}\`: ${sp.why}`);
      }
      sections.push("");
    }

    // Framework guidance (filtered to detected frameworks)
    const fwSections = formatFrameworkGuidance(content.frameworkGuidance, opts.frameworks);
    if (fwSections) {
      sections.push(fwSections);
    }
  }

  return sections.join("\n");
}

/**
 * Get language-matched few-shot examples for a task.
 */
export function languageFewShotsModule(opts: LanguageTuningOpts): string {
  const entries = resolveEntries(opts);
  if (entries.length === 0) return "";

  const shots: Array<{ lang: string; shot: LanguageFewShot }> = [];
  for (const { profile, content } of entries) {
    for (const shot of content.fewShots) {
      shots.push({ lang: profile.languageId, shot });
    }
  }
  if (shots.length === 0) return "";

  const lines: string[] = ["## Few-shot examples\n"];
  for (const { lang, shot } of shots.slice(0, 4)) {
    lines.push(`**${lang} — ${shot.scenario}:**`);
    lines.push("```");
    lines.push(shot.vulnerableCode);
    lines.push("```");
    lines.push(`Why: ${shot.explanation}\n`);
  }
  return lines.join("\n");
}

/**
 * Get language-specific investigation methodology.
 */
export function languageInvestigationModule(opts: LanguageTuningOpts): string {
  const entries = resolveEntries(opts);
  if (entries.length === 0) return "";

  const lines: string[] = ["## Language-specific investigation\n"];

  for (const { profile, content } of entries) {
    const hints = content.investigationHints;
    if (
      hints.instructions.length === 0 &&
      hints.grepPatterns.length === 0 &&
      hints.fileHints.length === 0
    ) {
      continue;
    }

    lines.push(`### ${profile.languageId}\n`);
    if (hints.grepPatterns.length > 0) {
      lines.push(`Grep for: ${hints.grepPatterns.map((p) => `\`${p}\``).join(", ")}`);
    }
    if (hints.fileHints.length > 0) {
      lines.push(`Check files: ${hints.fileHints.join(", ")}`);
    }
    for (const inst of hints.instructions) {
      lines.push(`- ${inst}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Get combined anti-hallucination constraints from language profiles.
 */
export function languageAntiHallucinationExtras(opts: LanguageTuningOpts): string[] {
  const entries = resolveEntries(opts);
  const extras: string[] = [];

  for (const { profile, content } of entries) {
    if (content.antiHallucinationExtra) {
      for (const line of content.antiHallucinationExtra) {
        extras.push(`[${profile.languageId}] ${line}`);
      }
    }
  }

  // Also add language-wide constraints
  if (opts.repoContext?.languages.length) {
    const profiles = getLanguageProfiles(opts.repoContext.languages);
    for (const p of profiles) {
      for (const line of p.generalAntiHallucination) {
        if (!extras.includes(`[${p.languageId}] ${line}`)) {
          extras.push(`[${p.languageId}] ${line}`);
        }
      }
    }
  }

  return extras;
}

/**
 * Get language-specific general search hints (for context-enricher).
 */
export function languageGeneralHintsModule(repoContext: RepoContext | undefined): string {
  if (!repoContext?.languages.length) return "";

  const profiles = getLanguageProfiles(repoContext.languages);
  if (profiles.length === 0) return "";

  const lines: string[] = ["## Language-specific search guidance\n"];
  for (const p of profiles) {
    if (p.generalHints.instructions.length === 0) continue;
    lines.push(`**${p.languageId}:**`);
    for (const inst of p.generalHints.instructions) {
      lines.push(`- ${inst}`);
    }
    if (p.generalHints.fileHints.length > 0) {
      lines.push(`- Key files: ${p.generalHints.fileHints.join(", ")}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

interface ResolvedEntry {
  profile: { languageId: string };
  content: VulnClassContent;
}

function resolveEntries(opts: LanguageTuningOpts): ResolvedEntry[] {
  if (!opts.repoContext?.languages.length) return [];

  const vulnClassIds = TASK_TO_VULN_CLASS[opts.taskId];
  if (!vulnClassIds) return [];

  const classes = Array.isArray(vulnClassIds) ? vulnClassIds : [vulnClassIds];
  const profiles = getLanguageProfiles(opts.repoContext.languages);
  const entries: ResolvedEntry[] = [];

  for (const profile of profiles) {
    for (const cls of classes) {
      const content = profile.vulnClasses[cls];
      if (content) {
        entries.push({ profile, content });
      }
    }
  }

  return entries;
}

function formatFrameworkGuidance(
  guidance: FrameworkGuidance[] | undefined,
  detectedFrameworks: string[] | undefined,
): string {
  if (!guidance?.length || !detectedFrameworks?.length) return "";

  const relevant = guidance.filter((fg) =>
    detectedFrameworks.some((f) => f.toLowerCase().includes(fg.framework.toLowerCase())),
  );
  if (relevant.length === 0) return "";

  const lines: string[] = ["**Framework guidance:**"];
  for (const fg of relevant) {
    lines.push(`- **${fg.framework}**:`);
    if (fg.defaults.length > 0) {
      lines.push(`  - Defaults: ${fg.defaults.join("; ")}`);
    }
    if (fg.pitfalls.length > 0) {
      lines.push(`  - Pitfalls: ${fg.pitfalls.join("; ")}`);
    }
    if (fg.configChecks.length > 0) {
      lines.push(`  - Check: ${fg.configChecks.join("; ")}`);
    }
  }
  lines.push("");
  return lines.join("\n");
}

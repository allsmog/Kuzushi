/**
 * Prompt accounting and reporting.
 *
 * Tracks token consumption per section of a rendered prompt,
 * emits warnings when prompts exceed configurable budgets,
 * and produces reports for observability.
 */

/** A measured section of a rendered prompt. */
export interface PromptSection {
  name: string;
  charCount: number;
  estimatedTokens: number;
}

/** Full report of a rendered prompt's composition. */
export interface PromptReport {
  sections: PromptSection[];
  totalChars: number;
  totalEstimatedTokens: number;
  warnings: string[];
}

/** Rough chars-per-token estimate for English text. */
const CHARS_PER_TOKEN = 4;

/** Default warning threshold in tokens. */
const DEFAULT_WARNING_THRESHOLD = 8000;

/**
 * Analyze a rendered prompt by splitting on section markers.
 *
 * Section markers are lines that start with `## ` or `# ` in the prompt.
 * Each section's character and estimated token count is measured.
 *
 * @param renderedPrompt - The fully rendered prompt string
 * @param warningThreshold - Token count above which a warning is emitted (default 8000)
 */
export function analyzePrompt(
  renderedPrompt: string,
  warningThreshold: number = DEFAULT_WARNING_THRESHOLD,
): PromptReport {
  const sections: PromptSection[] = [];
  const warnings: string[] = [];

  // Split on markdown headers to identify sections
  const sectionPattern = /^(#{1,3})\s+(.+)$/gm;
  let lastIndex = 0;
  let lastSectionName = "preamble";
  let match: RegExpExecArray | null;

  const matches: Array<{ name: string; index: number }> = [];
  while ((match = sectionPattern.exec(renderedPrompt)) !== null) {
    matches.push({ name: match[2].trim(), index: match.index });
  }

  for (let i = 0; i < matches.length; i++) {
    const sectionContent = renderedPrompt.slice(lastIndex, matches[i].index);
    if (sectionContent.trim().length > 0) {
      const charCount = sectionContent.length;
      sections.push({
        name: lastSectionName,
        charCount,
        estimatedTokens: Math.ceil(charCount / CHARS_PER_TOKEN),
      });
    }
    lastSectionName = matches[i].name;
    lastIndex = matches[i].index;
  }

  // Final section
  const remaining = renderedPrompt.slice(lastIndex);
  if (remaining.trim().length > 0) {
    const charCount = remaining.length;
    sections.push({
      name: lastSectionName,
      charCount,
      estimatedTokens: Math.ceil(charCount / CHARS_PER_TOKEN),
    });
  }

  // If no sections found, treat entire prompt as one section
  if (sections.length === 0) {
    sections.push({
      name: "prompt",
      charCount: renderedPrompt.length,
      estimatedTokens: Math.ceil(renderedPrompt.length / CHARS_PER_TOKEN),
    });
  }

  const totalChars = sections.reduce((sum, s) => sum + s.charCount, 0);
  const totalEstimatedTokens = sections.reduce((sum, s) => sum + s.estimatedTokens, 0);

  if (totalEstimatedTokens > warningThreshold) {
    warnings.push(
      `System prompt exceeds ${warningThreshold} tokens (~${totalEstimatedTokens} estimated)`,
    );
  }

  // Warn about large individual sections
  for (const section of sections) {
    if (section.estimatedTokens > warningThreshold * 0.5) {
      warnings.push(
        `Section "${section.name}" is large (~${section.estimatedTokens} tokens, ${Math.round((section.estimatedTokens / totalEstimatedTokens) * 100)}% of total)`,
      );
    }
  }

  return { sections, totalChars, totalEstimatedTokens, warnings };
}

/**
 * Format a prompt report as a human-readable string.
 */
export function formatPromptReport(report: PromptReport): string {
  const lines: string[] = [];
  lines.push(
    `Prompt Report: ${report.totalEstimatedTokens} estimated tokens (${report.totalChars} chars)`,
  );
  lines.push("\u2500".repeat(60));

  for (const section of report.sections) {
    const pct = Math.round((section.estimatedTokens / report.totalEstimatedTokens) * 100);
    lines.push(`  ${section.name}: ~${section.estimatedTokens} tokens (${pct}%)`);
  }

  if (report.warnings.length > 0) {
    lines.push("");
    lines.push("Warnings:");
    for (const warning of report.warnings) {
      lines.push(`  \u26A0 ${warning}`);
    }
  }

  return lines.join("\n");
}

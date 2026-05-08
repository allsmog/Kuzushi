import { readFileSync } from "node:fs";
import path from "node:path";

/** Parsed organization precedents. */
export interface Precedents {
  hardExclusions: string[];
  signalCriteria: string[];
  architecturalPrecedents: string[];
}

const EMPTY_PRECEDENTS: Precedents = {
  hardExclusions: [],
  signalCriteria: [],
  architecturalPrecedents: [],
};

/**
 * Load precedents from `.kuzushi/precedents.txt` in the project root
 * and optionally `~/.kuzushi/precedents.txt` globally.
 * Project-level precedents are appended after global ones.
 */
export function loadPrecedents(repoRoot: string): Precedents {
  const globalPath = path.join(
    process.env["HOME"] ?? process.env["USERPROFILE"] ?? "",
    ".kuzushi",
    "precedents.txt",
  );
  const projectPath = path.join(repoRoot, ".kuzushi", "precedents.txt");

  const globalPrecedents = parsePrecedentsFile(globalPath);
  const projectPrecedents = parsePrecedentsFile(projectPath);

  return mergePrecedents(globalPrecedents, projectPrecedents);
}

/**
 * Format precedents into prompt lines for injection into triage/verify prompts.
 * Returns lines to insert, or empty array if no precedents are available.
 */
export function formatPrecedentsForPrompt(precedents: Precedents | undefined): string[] {
  if (!precedents) return [];

  const hasContent =
    precedents.architecturalPrecedents.length > 0 || precedents.signalCriteria.length > 0;

  if (!hasContent) return [];

  const lines: string[] = ["## Organization Security Precedents"];

  if (precedents.architecturalPrecedents.length > 0) {
    lines.push("### Architectural Facts");
    for (const item of precedents.architecturalPrecedents) {
      lines.push(`- ${item}`);
    }
  }

  if (precedents.signalCriteria.length > 0) {
    lines.push("### Signal Quality Criteria");
    for (const item of precedents.signalCriteria) {
      lines.push(`- ${item}`);
    }
  }

  return lines;
}

function parsePrecedentsFile(filePath: string): Precedents {
  let content: string;
  try {
    content = readFileSync(filePath, "utf-8");
  } catch {
    return { ...EMPTY_PRECEDENTS };
  }

  const result: Precedents = {
    hardExclusions: [],
    signalCriteria: [],
    architecturalPrecedents: [],
  };

  let currentSection: keyof Precedents | null = null;

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();

    if (line.startsWith("## Hard Exclusions")) {
      currentSection = "hardExclusions";
      continue;
    }
    if (line.startsWith("## Signal Quality Criteria")) {
      currentSection = "signalCriteria";
      continue;
    }
    if (line.startsWith("## Architectural Precedents")) {
      currentSection = "architecturalPrecedents";
      continue;
    }

    if (currentSection && line.startsWith("- ")) {
      const item = line.slice(2).trim();
      if (item) {
        result[currentSection].push(item);
      }
    }
  }

  return result;
}

function mergePrecedents(global: Precedents, project: Precedents): Precedents {
  return {
    hardExclusions: [...global.hardExclusions, ...project.hardExclusions],
    signalCriteria: [...global.signalCriteria, ...project.signalCriteria],
    architecturalPrecedents: [
      ...global.architecturalPrecedents,
      ...project.architecturalPrecedents,
    ],
  };
}

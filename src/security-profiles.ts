import { readFileSync } from "node:fs";
import path from "node:path";

/** A domain-specific security vulnerability category profile. */
export interface SecurityProfile {
  name: string;
  items: string[];
  appliesTo?: string[];
}

/**
 * Load security profiles from `.kuzushi/security-profiles.txt` in the project root.
 * Format: markdown sections (`## Category Name` + bullet items).
 * Optional `appliesTo:` directive on the section header line: `## Category Name [appliesTo: task-id-1, task-id-2]`
 */
export function loadSecurityProfiles(repoRoot: string): SecurityProfile[] {
  const filePath = path.join(repoRoot, ".kuzushi", "security-profiles.txt");
  return parseSecurityProfilesFile(filePath);
}

/**
 * Filter profiles to those applicable to a given task ID.
 * Profiles with no `appliesTo` apply to all tasks (wildcard).
 */
export function getProfilesForTask(
  profiles: SecurityProfile[],
  taskId: string,
): SecurityProfile[] {
  return profiles.filter(
    (p) =>
      !p.appliesTo ||
      p.appliesTo.length === 0 ||
      p.appliesTo.includes("*") ||
      p.appliesTo.includes(taskId),
  );
}

/**
 * Format security profiles into prompt lines for injection into scanner/analysis prompts.
 */
export function formatProfilesForPrompt(profiles: SecurityProfile[]): string[] {
  if (profiles.length === 0) return [];

  const lines: string[] = ["## Domain-Specific Security Categories"];

  for (const profile of profiles) {
    lines.push(`### ${profile.name}`);
    for (const item of profile.items) {
      lines.push(`- ${item}`);
    }
  }

  return lines;
}

function parseSecurityProfilesFile(filePath: string): SecurityProfile[] {
  let content: string;
  try {
    content = readFileSync(filePath, "utf-8");
  } catch {
    return [];
  }

  const profiles: SecurityProfile[] = [];
  let current: SecurityProfile | null = null;

  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();

    if (line.startsWith("## ")) {
      if (current && current.items.length > 0) {
        profiles.push(current);
      }

      const { name, appliesTo } = parseHeaderLine(line.slice(3).trim());
      current = { name, items: [], appliesTo };
      continue;
    }

    if (current && line.startsWith("- ")) {
      const item = line.slice(2).trim();
      if (item) {
        current.items.push(item);
      }
    }
  }

  if (current && current.items.length > 0) {
    profiles.push(current);
  }

  return profiles;
}

function parseHeaderLine(header: string): { name: string; appliesTo?: string[] } {
  const bracketMatch = header.match(/^(.+?)\s*\[appliesTo:\s*(.+?)\]\s*$/);
  if (bracketMatch) {
    const name = bracketMatch[1].trim();
    const appliesTo = bracketMatch[2]
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    return { name, appliesTo: appliesTo.length > 0 ? appliesTo : undefined };
  }
  return { name: header };
}

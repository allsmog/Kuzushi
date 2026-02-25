import type { Finding } from "./types.js";

const RULE_STOP_WORDS = new Set([
  "codeql",
  "semgrep",
  "security",
  "audit",
  "vulnerability",
  "vuln",
  "rule",
  "query",
  "javascript",
  "js",
  "typescript",
  "ts",
  "python",
  "py",
  "go",
  "java",
  "cpp",
  "cs",
  "dotnet",
  "csharp",
  "ruby",
  "rust",
  "lang",
]);

/**
 * Rank findings and dedupe in two passes:
 * 1) exact fingerprint dedupe
 * 2) cross-scanner dedupe at same location using rule/cwe signature keys
 */
export function selectTopFindings(findings: Finding[], maxFindings?: number): Finding[] {
  const byFingerprint = new Map<string, Finding>();

  for (const finding of findings) {
    const existing = byFingerprint.get(finding.fingerprint);
    if (!existing || finding.score > existing.score) {
      byFingerprint.set(finding.fingerprint, finding);
    }
  }

  const ranked = [...byFingerprint.values()]
    .sort((a, b) => b.score - a.score);

  const selected: Finding[] = [];
  const seenCrossScannerKeys = new Set<string>();

  for (const finding of ranked) {
    const keys = buildCrossScannerKeys(finding);
    if (keys.some((key) => seenCrossScannerKeys.has(key))) {
      continue;
    }

    selected.push(finding);
    for (const key of keys) {
      seenCrossScannerKeys.add(key);
    }

    if (maxFindings !== undefined && selected.length >= maxFindings) {
      break;
    }
  }

  return selected.slice(0, maxFindings);
}

function buildCrossScannerKeys(finding: Finding): string[] {
  const filePath = normalizePathForKey(finding.filePath);
  const line = Number.isFinite(finding.startLine) ? Math.max(1, Math.floor(finding.startLine)) : 1;
  const keys = new Set<string>();

  const normalizedCwe = normalizeCweForKey(finding.cwe);
  if (normalizedCwe.length > 0) {
    keys.add(`loc+cwe|${filePath}|${line}|${normalizedCwe.join(",")}`);
  }

  if (keys.size === 0) {
    const normalizedRule = normalizeRuleForKey(finding.ruleId);
    if (normalizedRule) {
      keys.add(`loc+rule|${filePath}|${line}|${normalizedRule}`);
    }
  }

  if (keys.size === 0) {
    const normalizedMessage = normalizeMessageForKey(finding.message);
    if (normalizedMessage) {
      keys.add(`loc+msg|${filePath}|${line}|${normalizedMessage}`);
    }
  }

  return [...keys];
}

function normalizePathForKey(filePath: string): string {
  return filePath
    .replace(/\\/g, "/")
    .replace(/^\/+/, "")
    .toLowerCase();
}

function normalizeCweForKey(cwe: string[]): string[] {
  const normalized = cwe
    .map((item) => {
      const match = item.toUpperCase().match(/CWE-(\d+)/);
      return match ? `CWE-${Number.parseInt(match[1], 10)}` : "";
    })
    .filter(Boolean);

  return [...new Set(normalized)].sort((a, b) => a.localeCompare(b));
}

function normalizeRuleForKey(ruleId: string): string {
  const cleaned = ruleId
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();

  if (!cleaned) {
    return "";
  }

  const tokens = cleaned
    .split(/\s+/)
    .filter((token) => token.length > 0 && !RULE_STOP_WORDS.has(token));

  if (tokens.length === 0) {
    return "";
  }

  return tokens.slice(-4).join("-");
}

function normalizeMessageForKey(message: string): string {
  return message
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .split(/\s+/)
    .slice(0, 6)
    .join("-");
}

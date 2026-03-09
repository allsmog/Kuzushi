import type { Finding } from "./types.js";

export interface FpFilterResult {
  kept: Finding[];
  excluded: Finding[];
}

interface ExclusionRule {
  id: string;
  description: string;
  match: (finding: Finding) => boolean;
}

const DOS_PATTERNS = /\b(dos|denial.of.service|resource.exhaustion|amplification.attack|billion.laughs|xml.bomb)\b/i;
const RATE_LIMIT_PATTERNS = /(rate.limit|throttl|service.overload|brute.?force|account.lockout)/i;
const RESOURCE_LEAK_PATTERNS = /\b(resource.leak|memory.leak|file.descriptor.leak|connection.leak|handle.leak|unclosed)\b/i;
const OPEN_REDIRECT_PATTERNS = /\b(open.redirect|url.redirect|unvalidated.redirect)\b/i;
const MEMORY_SAFETY_PATTERNS = /\b(buffer.overflow|use.after.free|double.free|heap.overflow|stack.overflow|out.of.bounds|null.pointer.deref)\b/i;
const REGEX_INJECTION_PATTERNS = /\b(regex.injection|redos|regular.expression.denial)\b/i;
const NON_C_LANGUAGES = /\.(ts|tsx|js|jsx|py|rb|java|kt|go|rs|cs|php|swift|scala|dart|lua|pl|r|ex|exs|clj|erl|hs|ml|fs|jl)$/i;
const TEST_PATH_PATTERNS = /(?:^|[/\\])(?:test|tests|spec|specs|__tests__|__mocks__|__fixtures__|fixtures|mocks|e2e|cypress|playwright|vitest|jest)[/\\]/i;
const DOC_PATH_PATTERNS = /(?:^|[/\\])(?:docs?|documentation|README|CHANGELOG|CONTRIBUTING|wiki)[/\\]|\.(?:md|mdx|rst|txt|adoc)$/i;
const CLIENT_SIDE_PATTERNS = /(?:^|[/\\])(?:public|static|assets|dist|build|out|client|frontend|www)[/\\]/i;

const EXCLUSION_RULES: ExclusionRule[] = [
  {
    id: "dos-resource-exhaustion",
    description: "DoS / resource exhaustion findings (low exploitability in most contexts)",
    match: (f) => DOS_PATTERNS.test(f.message) || DOS_PATTERNS.test(f.ruleId),
  },
  {
    id: "rate-limiting",
    description: "Rate limiting / service overload findings",
    match: (f) => RATE_LIMIT_PATTERNS.test(f.message) || RATE_LIMIT_PATTERNS.test(f.ruleId),
  },
  {
    id: "resource-leak",
    description: "Resource leaks (memory, file, connection) — functional bugs, not security",
    match: (f) => RESOURCE_LEAK_PATTERNS.test(f.message) || RESOURCE_LEAK_PATTERNS.test(f.ruleId),
  },
  {
    id: "open-redirect",
    description: "Open redirects (low impact in most contexts)",
    match: (f) => OPEN_REDIRECT_PATTERNS.test(f.message) || OPEN_REDIRECT_PATTERNS.test(f.ruleId),
  },
  {
    id: "memory-safety-non-native",
    description: "Memory safety findings in non-C/C++ code",
    match: (f) =>
      (MEMORY_SAFETY_PATTERNS.test(f.message) || MEMORY_SAFETY_PATTERNS.test(f.ruleId))
      && NON_C_LANGUAGES.test(f.filePath),
  },
  {
    id: "regex-injection",
    description: "Regex injection / ReDoS findings",
    match: (f) => REGEX_INJECTION_PATTERNS.test(f.message) || REGEX_INJECTION_PATTERNS.test(f.ruleId),
  },
  {
    id: "ssrf-client-side",
    description: "SSRF in HTML/client-side files",
    match: (f) =>
      (/\bssrf\b/i.test(f.message) || /\bssrf\b/i.test(f.ruleId))
      && (CLIENT_SIDE_PATTERNS.test(f.filePath) || /\.html?$/i.test(f.filePath)),
  },
  {
    id: "doc-files",
    description: "Findings in documentation/markdown files",
    match: (f) => DOC_PATH_PATTERNS.test(f.filePath),
  },
  {
    id: "test-files",
    description: "Findings in test/spec directories",
    match: (f) => TEST_PATH_PATTERNS.test(f.filePath),
  },
];

/**
 * Deterministic regex-based FP suppression layer.
 * Eliminates known false-positive categories before findings enter the LLM triage queue.
 */
export class HardExclusionFilter {
  private readonly rules: ExclusionRule[];
  private readonly customPatterns: RegExp[];

  constructor(customExclusions?: string[]) {
    this.rules = [...EXCLUSION_RULES];
    this.customPatterns = (customExclusions ?? [])
      .filter(Boolean)
      .map((pattern) => new RegExp(pattern, "i"));
  }

  filterFindings(findings: Finding[]): FpFilterResult {
    const kept: Finding[] = [];
    const excluded: Finding[] = [];

    for (const finding of findings) {
      if (this.shouldExclude(finding)) {
        excluded.push(finding);
      } else {
        kept.push(finding);
      }
    }

    return { kept, excluded };
  }

  private shouldExclude(finding: Finding): boolean {
    for (const rule of this.rules) {
      if (rule.match(finding)) return true;
    }
    for (const pattern of this.customPatterns) {
      if (pattern.test(finding.message) || pattern.test(finding.ruleId)) return true;
    }
    return false;
  }
}

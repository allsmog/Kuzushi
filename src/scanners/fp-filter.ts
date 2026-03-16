import type { Finding, SuppressionReason } from "./types.js";

export interface FpFilterResult {
  kept: Finding[];
  hardExcluded: Finding[];
  softSuppressed: Finding[];
}

interface ExclusionRule {
  id: string;
  description: string;
  kind: "hard" | "soft";
  scorePenalty?: number;
  match: (finding: Finding) => boolean;
}

const DOS_PATTERNS = /\b(dos|denial.of.service|resource.exhaustion|amplification.attack|billion.laughs|xml.bomb)\b/i;
const RATE_LIMIT_PATTERNS = /(rate.limit|throttl|service.overload|brute.?force|account.lockout)/i;
const RESOURCE_LEAK_PATTERNS = /\b(resource.leak|memory.leak|file.descriptor.leak|connection.leak|handle.leak|unclosed)\b/i;
const OPEN_REDIRECT_PATTERNS = /\b(open.redirect|url.redirect|unvalidated.redirect)\b/i;
const AUTH_REDIRECT_CONTEXT = /\b(oauth|redirect_uri|login|saml|callback|sso|oidc|auth)\b/i;
const MEMORY_SAFETY_PATTERNS = /\b(buffer.overflow|use.after.free|double.free|heap.overflow|stack.overflow|out.of.bounds|null.pointer.deref)\b/i;
const REGEX_INJECTION_PATTERNS = /\b(regex.injection|redos|regular.expression.denial)\b/i;
const NON_C_LANGUAGES = /\.(ts|tsx|js|jsx|py|rb|java|kt|go|rs|cs|php|swift|scala|dart|lua|pl|r|ex|exs|clj|erl|hs|ml|fs|jl)$/i;
const TEST_PATH_PATTERNS = /(?:^|[/\\])(?:test|tests|spec|specs|__tests__|__mocks__|__fixtures__|fixtures|mocks|e2e|cypress|playwright|vitest|jest)[/\\]/i;
const DOC_PATH_PATTERNS = /(?:^|[/\\])(?:docs?|documentation|README|CHANGELOG|CONTRIBUTING|wiki)[/\\]|\.(?:md|mdx|rst|txt|adoc)$/i;
const CLIENT_SIDE_PATTERNS = /(?:^|[/\\])(?:public|static|assets|dist|build|out|client|frontend|www)[/\\]/i;
const GENERATED_VENDORED_PATTERNS = /(?:^|[/\\])(?:dist|build|\.next|\.nuxt|vendor|third_party|\.generated|node_modules)[/\\]|\.bundle\.js$/i;

const EXCLUSION_RULES: ExclusionRule[] = [
  {
    id: "dos-resource-exhaustion",
    description: "DoS / resource exhaustion findings (low exploitability in most contexts)",
    kind: "hard",
    match: (f) => DOS_PATTERNS.test(f.message) || DOS_PATTERNS.test(f.ruleId),
  },
  {
    id: "rate-limiting",
    description: "Rate limiting / service overload findings",
    kind: "hard",
    match: (f) => RATE_LIMIT_PATTERNS.test(f.message) || RATE_LIMIT_PATTERNS.test(f.ruleId),
  },
  {
    id: "resource-leak",
    description: "Resource leaks (memory, file, connection) — functional bugs, not security",
    kind: "hard",
    match: (f) => RESOURCE_LEAK_PATTERNS.test(f.message) || RESOURCE_LEAK_PATTERNS.test(f.ruleId),
  },
  {
    id: "open-redirect",
    description: "Open redirects (low impact in most contexts) — except auth-related redirects",
    kind: "soft",
    scorePenalty: 15,
    match: (f) =>
      (OPEN_REDIRECT_PATTERNS.test(f.message) || OPEN_REDIRECT_PATTERNS.test(f.ruleId))
      && !AUTH_REDIRECT_CONTEXT.test(f.message)
      && !AUTH_REDIRECT_CONTEXT.test(f.filePath)
      && !AUTH_REDIRECT_CONTEXT.test(f.evidence ?? ""),
  },
  {
    id: "memory-safety-non-native",
    description: "Memory safety findings in non-C/C++ code",
    kind: "hard",
    match: (f) =>
      (MEMORY_SAFETY_PATTERNS.test(f.message) || MEMORY_SAFETY_PATTERNS.test(f.ruleId))
      && NON_C_LANGUAGES.test(f.filePath),
  },
  {
    id: "regex-injection",
    description: "Regex injection / ReDoS findings",
    kind: "hard",
    match: (f) => REGEX_INJECTION_PATTERNS.test(f.message) || REGEX_INJECTION_PATTERNS.test(f.ruleId),
  },
  {
    id: "ssrf-client-side",
    description: "SSRF in HTML/client-side files",
    kind: "soft",
    scorePenalty: 15,
    match: (f) =>
      (/\bssrf\b/i.test(f.message) || /\bssrf\b/i.test(f.ruleId))
      && (CLIENT_SIDE_PATTERNS.test(f.filePath) || /\.html?$/i.test(f.filePath)),
  },
  {
    id: "doc-files",
    description: "Findings in documentation/markdown files",
    kind: "hard",
    match: (f) => DOC_PATH_PATTERNS.test(f.filePath),
  },
  {
    id: "test-files",
    description: "Findings in test/spec directories",
    kind: "hard",
    match: (f) => TEST_PATH_PATTERNS.test(f.filePath),
  },
  {
    id: "generated-vendored",
    description: "Findings in generated, vendored, or build output directories",
    kind: "hard",
    match: (f) => GENERATED_VENDORED_PATTERNS.test(f.filePath),
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
    const hardExcluded: Finding[] = [];
    const softSuppressed: Finding[] = [];

    for (const finding of findings) {
      const matches = this.matchRules(finding);
      if (matches.length === 0) {
        kept.push(ensureAdjustedScore(finding));
        continue;
      }

      const hardMatches = matches.filter((rule) => rule.kind === "hard");
      if (hardMatches.length > 0) {
        hardExcluded.push(applySuppressionMetadata(finding, hardMatches));
        continue;
      }

      const suppressed = applySuppressionMetadata(finding, matches);
      softSuppressed.push(suppressed);
      kept.push(suppressed);
    }

    return { kept, hardExcluded, softSuppressed };
  }

  private matchRules(finding: Finding): ExclusionRule[] {
    const matches: ExclusionRule[] = [];

    for (const rule of this.rules) {
      if (rule.match(finding)) {
        matches.push(rule);
      }
    }
    for (const pattern of this.customPatterns) {
      if (pattern.test(finding.message) || pattern.test(finding.ruleId)) {
        matches.push({
          id: `custom:${pattern.source}`,
          description: `Custom exclusion matched: /${pattern.source}/i`,
          kind: "hard",
          match: () => true,
        });
      }
    }

    return matches;
  }
}

function ensureAdjustedScore(finding: Finding): Finding {
  return {
    ...finding,
    adjustedScore: finding.adjustedScore ?? finding.score,
  };
}

function applySuppressionMetadata(finding: Finding, rules: ExclusionRule[]): Finding {
  const base = ensureAdjustedScore(finding);
  const suppressionReasons: SuppressionReason[] = [
    ...(base.suppressionReasons ?? []),
    ...rules.map((rule) => ({
      id: rule.id,
      kind: rule.kind,
      description: rule.description,
      scorePenalty: rule.scorePenalty,
    })),
  ];

  const totalPenalty = rules.reduce((sum, rule) => sum + (rule.kind === "soft" ? rule.scorePenalty ?? 0 : 0), 0);
  return {
    ...base,
    adjustedScore: Math.max(0, (base.adjustedScore ?? base.score) - totalPenalty),
    suppressionReasons,
  };
}

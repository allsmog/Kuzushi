/**
 * Language-specific prompt tuning types.
 *
 * Each language profile provides per-vulnerability-class guidance:
 * sinks, safe patterns, investigation hints, few-shot examples,
 * and framework-specific advice.
 */

/** A language-specific dangerous sink/API for a vulnerability class. */
export interface LanguageSink {
  /** The API or function name */
  api: string;
  /** Why it's dangerous in this context */
  risk: string;
  /** Whether this is a shell-invoking variant (for command injection) */
  shellInvoking?: boolean;
  /** CWEs this sink relates to */
  cwes?: string[];
}

/** A safe alternative that should NOT be flagged. */
export interface LanguageSafePattern {
  api: string;
  why: string;
}

/** Investigation methodology hints for the LLM agent. */
export interface InvestigationHint {
  /** Grep patterns specific to this language (regex strings) */
  grepPatterns: string[];
  /** Files or paths to prioritize reading */
  fileHints: string[];
  /** Step-by-step investigation instructions */
  instructions: string[];
}

/** A few-shot example for a specific (language, vuln-class) pair. */
export interface LanguageFewShot {
  /** Short scenario label */
  scenario: string;
  /** The vulnerable code snippet */
  vulnerableCode: string;
  /** Why it's vulnerable */
  explanation: string;
}

/** Framework-specific security guidance within a language. */
export interface FrameworkGuidance {
  framework: string;
  /** Secure defaults the framework provides */
  defaults: string[];
  /** Known pitfalls or bypass patterns */
  pitfalls: string[];
  /** Config files/settings to check */
  configChecks: string[];
}

/** Content for a specific vulnerability class within a language. */
export interface VulnClassContent {
  /** Dangerous sinks/APIs to detect */
  sinks: LanguageSink[];
  /** Safe patterns to NOT flag */
  safePatterns: LanguageSafePattern[];
  /** Investigation methodology hints */
  investigationHints: InvestigationHint;
  /** Few-shot examples */
  fewShots: LanguageFewShot[];
  /** Framework-specific guidance (filtered by detected frameworks) */
  frameworkGuidance?: FrameworkGuidance[];
  /** Additional anti-hallucination constraints */
  antiHallucinationExtra?: string[];
}

/** Complete language security profile. */
export interface LanguageProfile {
  /** Language identifier matching RepoContext.languages values */
  languageId: string;
  /** Alternative identifiers */
  aliases: string[];
  /** Vulnerability class content, keyed by canonical vuln class ID */
  vulnClasses: Record<string, VulnClassContent>;
  /** Language-wide investigation hints (not vuln-specific) */
  generalHints: InvestigationHint;
  /** Language-wide anti-hallucination constraints */
  generalAntiHallucination: string[];
}

import type { Finding } from "./types.js";
import type { TriageResult, Verdict } from "../types.js";

export type DesignDecisionCategory =
  | "security-toggle"
  | "env-var-toggle"
  | "rfc-compliant"
  | "backward-compat"
  | "intentional-relaxation";

export interface DesignDecisionRule {
  id: string;
  category: DesignDecisionCategory;
  description: string;
  match: (finding: Finding) => boolean;
  rationale: (finding: Finding) => string;
}

export interface ClassificationResult {
  autoClassified: Array<{ finding: Finding; result: TriageResult; ruleId: string }>;
  remaining: Finding[];
}

// ── Shared helpers ──────────────────────────────────────────────────────────

function buildMatchText(finding: Finding): string {
  return [finding.ruleId, finding.message, finding.evidence ?? ""].join(" ");
}

/**
 * Safety guard: if the finding mentions exploit-indicative vulnerability classes,
 * do NOT auto-classify — let the LLM decide.
 */
const EXPLOIT_INDICATORS =
  /\b(injection|rce|remote.code.execution|arbitrary.code|command.injection|sql.injection|xss|cross.site|deserialization|ssrf|path.traversal|lfi|rfi)\b/i;

function hasExploitIndicators(text: string): boolean {
  return EXPLOIT_INDICATORS.test(text);
}

// ── Pattern regexes ─────────────────────────────────────────────────────────

const SECURITY_TOGGLE_FLAGS =
  /\b(INSECURE_MODE|DISABLE_TLS|ALLOW_INSECURE|SKIP_VERIFY|NO_AUTH|UNSAFE_MODE|DISABLE_AUTH|ALLOW_HTTP|DISABLE_SECURITY|SKIP_AUTH|INSECURE_SKIP_VERIFY|DISABLE_CERT_CHECK|ALLOW_UNAUTH|NO_SSL|SKIP_TLS|DISABLE_HTTPS_ONLY)\b/i;

const CONFIG_CONTEXT =
  /\b(config|option|flag|setting|toggle|env|environment|variable|parameter|override|fallback)\b/i;

// Case-sensitive: environment variable names are literal.
const ENV_VAR_TOGGLES =
  /\b(NODE_TLS_REJECT_UNAUTHORIZED|GIT_SSL_NO_VERIFY|PYTHONHTTPSVERIFY|REQUESTS_CA_BUNDLE|JAVA_TOOL_OPTIONS|SSL_CERT_FILE|CURL_CA_BUNDLE|NODE_EXTRA_CA_CERTS|PIP_TRUSTED_HOST|npm_config_strict_ssl|GONOSUMCHECK)\b/;

const RFC_PATTERNS =
  /\b(RFC.?7591|dynamic.client.registration|client_registration_endpoint)\b/i;

const LEGACY_PATTERNS =
  /\b(backward.?compat|legacy.protocol|deprecated.auth|fallback.mode|compat.?mode|legacy.support)\b/i;

const COMPAT_CONTEXT =
  /\b(compat|legacy|fallback|deprecated|migration)\b/i;

const RELAXATION_PARAMS =
  /\b(rejectUnauthorized|verify_ssl|CURLOPT_SSL_VERIFYPEER|ssl_verify|tls_verify|check_hostname|verify_certs|insecure_skip_tls_verify)\b/i;

const CONFIGURABLE_CONTEXT =
  /\b(process\.env|getenv|os\.environ|config\.|options\.|settings\.)\b/i;

// ── Rules ───────────────────────────────────────────────────────────────────

const DESIGN_DECISION_RULES: DesignDecisionRule[] = [
  {
    id: "security-toggle-flags",
    category: "security-toggle",
    description: "Security toggle flag in configuration context",
    match(finding) {
      const text = buildMatchText(finding);
      if (hasExploitIndicators(text)) return false;
      return SECURITY_TOGGLE_FLAGS.test(text) && CONFIG_CONTEXT.test(text);
    },
    rationale(finding) {
      const text = buildMatchText(finding);
      const flagMatch = text.match(SECURITY_TOGGLE_FLAGS);
      const flag = flagMatch?.[0] ?? "security toggle";
      return (
        `Auto-classified as by_design: security toggle flag \`${flag}\` detected in configuration context. ` +
        `This pattern represents an intentional, user-controllable security behavior toggle, not an exploitable vulnerability.`
      );
    },
  },
  {
    id: "env-var-security-toggle",
    category: "env-var-toggle",
    description: "Well-known environment variable security toggle",
    match(finding) {
      const text = buildMatchText(finding);
      if (hasExploitIndicators(text)) return false;
      return ENV_VAR_TOGGLES.test(text);
    },
    rationale(finding) {
      const text = buildMatchText(finding);
      const varMatch = text.match(ENV_VAR_TOGGLES);
      const varName = varMatch?.[0] ?? "environment variable";
      return (
        `Auto-classified as by_design: well-known environment variable \`${varName}\` is an intentional security toggle. ` +
        `Operators set this variable to opt into relaxed security for specific deployment contexts (e.g., self-signed certs in dev).`
      );
    },
  },
  {
    id: "rfc-compliant-behavior",
    category: "rfc-compliant",
    description: "RFC-compliant protocol behavior",
    match(finding) {
      const text = buildMatchText(finding);
      if (hasExploitIndicators(text)) return false;
      return RFC_PATTERNS.test(text);
    },
    rationale(finding) {
      const text = buildMatchText(finding);
      const rfcMatch = text.match(RFC_PATTERNS);
      const pattern = rfcMatch?.[0] ?? "RFC-compliant behavior";
      return (
        `Auto-classified as by_design: \`${pattern}\` is standards-compliant protocol behavior. ` +
        `This follows published RFC specifications and is expected behavior, not a vulnerability.`
      );
    },
  },
  {
    id: "backward-compat-legacy",
    category: "backward-compat",
    description: "Backward-compatibility or legacy protocol support",
    match(finding) {
      const text = buildMatchText(finding);
      if (hasExploitIndicators(text)) return false;
      const fullText = text + " " + finding.filePath;
      return LEGACY_PATTERNS.test(text) && COMPAT_CONTEXT.test(fullText);
    },
    rationale(finding) {
      const text = buildMatchText(finding);
      const legacyMatch = text.match(LEGACY_PATTERNS);
      const pattern = legacyMatch?.[0] ?? "legacy support";
      return (
        `Auto-classified as by_design: \`${pattern}\` is intentional backward-compatibility support. ` +
        `This pattern maintains compatibility with older clients or protocols as a deliberate architectural decision.`
      );
    },
  },
  {
    id: "intentional-relaxation-config",
    category: "intentional-relaxation",
    description: "Intentional security relaxation via configuration parameter",
    match(finding) {
      const text = buildMatchText(finding);
      if (hasExploitIndicators(text)) return false;
      return RELAXATION_PARAMS.test(text) && CONFIGURABLE_CONTEXT.test(text);
    },
    rationale(finding) {
      const text = buildMatchText(finding);
      const paramMatch = text.match(RELAXATION_PARAMS);
      const param = paramMatch?.[0] ?? "security parameter";
      return (
        `Auto-classified as by_design: \`${param}\` is gated by environment/configuration and represents ` +
        `an intentional operator-controlled security relaxation, not an unconditional vulnerability.`
      );
    },
  },
];

// ── Classifier ──────────────────────────────────────────────────────────────

/**
 * Deterministic regex-based classifier for design-decision findings.
 * Runs before LLM triage to auto-assign `by_design` verdict for
 * well-known intentional security patterns, saving LLM cost.
 */
export class DesignDecisionClassifier {
  private readonly rules: DesignDecisionRule[];

  constructor(rules: DesignDecisionRule[] = DESIGN_DECISION_RULES) {
    this.rules = rules;
  }

  classify(findings: Finding[]): ClassificationResult {
    const autoClassified: ClassificationResult["autoClassified"] = [];
    const remaining: Finding[] = [];

    for (const finding of findings) {
      const matchedRule = this.firstMatch(finding);
      if (matchedRule) {
        autoClassified.push({
          finding,
          result: buildByDesignResult(finding, matchedRule),
          ruleId: matchedRule.id,
        });
      } else {
        remaining.push(finding);
      }
    }

    return { autoClassified, remaining };
  }

  private firstMatch(finding: Finding): DesignDecisionRule | undefined {
    for (const rule of this.rules) {
      if (rule.match(finding)) return rule;
    }
    return undefined;
  }
}

function buildByDesignResult(finding: Finding, rule: DesignDecisionRule): TriageResult {
  return {
    fingerprint: finding.fingerprint,
    verdict: "by_design" as Verdict,
    confidence: 0.85,
    rationale: rule.rationale(finding),
    verificationSteps: [],
    fixPatch: null,
  };
}

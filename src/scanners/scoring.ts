const SEVERITY_SCORE: Record<string, number> = { ERROR: 3, WARNING: 2, INFO: 1 };
const LIKELIHOOD_SCORE: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const IMPACT_SCORE: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const SUBCATEGORY_SCORE: Record<string, number> = { vuln: 2, audit: 1 };

/**
 * CWE frequency multipliers based on WooYun-Legacy empirical data (88,636 cases).
 * Higher multipliers for vulnerability types that appear more frequently in real-world exploits.
 */
const CWE_FREQUENCY_MULTIPLIER: Record<string, number> = {
  "89":   1.3,   // SQLi — 27,732 cases (31.3%)
  "78":   1.25,  // Command injection — 6,826 cases (7.7%)
  "434":  1.2,   // File upload — 2,711 cases (3.1%) but high impact
  "94":   1.2,   // Code injection
  "502":  1.2,   // Deserialization
  "862":  1.15,  // Missing authz — 14,377 cases (16.2%)
  "287":  1.15,  // Auth bypass
  "798":  1.15,  // Hardcoded credentials
  "1321": 1.15,  // Prototype pollution
  "95":   1.15,  // Eval injection
  "1336": 1.15,  // SSTI
  "79":   1.1,   // XSS — 7,532 cases (8.5%)
  "918":  1.1,   // SSRF
  "362":  1.1,   // Race condition
  "639":  1.1,   // IDOR
  "943":  1.1,   // NoSQL injection
  "22":   1.05,  // Path traversal — 2,854 cases (3.2%)
  "327":  1.05,  // Weak crypto
  "915":  1.05,  // Mass assignment
  "200":  1.0,   // Info disclosure — 7,337 cases but lower direct impact
  "611":  1.0,   // XXE
  "352":  0.95,  // CSRF — context-dependent
  "16":   0.9,   // Misconfig
  // Memory-safety / deep semantic vulnerability classes
  "787":  1.3,   // Out-of-bounds write — often RCE
  "119":  1.3,   // Buffer overflow (generic) — RCE
  "416":  1.3,   // Use after free — RCE
  "190":  1.25,  // Integer overflow/wraparound
  "191":  1.25,  // Integer underflow
  "681":  1.2,   // Incorrect numeric type conversion
  "704":  1.2,   // Incorrect type conversion / type confusion
  "125":  1.15,  // Out-of-bounds read — info leak
  "693":  1.15,  // Protection mechanism failure
  "476":  1.1,   // NULL pointer dereference — DoS, sometimes RCE
  "672":  1.1,   // Operation on expired resource
};

/**
 * High-risk parameter names that indicate attacker-controlled input
 * reaching security-sensitive sinks. Returns a boost value (0-1).
 */
const HIGH_RISK_PARAMS = /\b(url|uri|redirect|callback|next|return_to|dest|target|path|file|filename|template|query|cmd|command|host|hostname|domain|ip|address|sql|ldap|xpath|eval|code|script|payload)\b/i;
const MEDIUM_RISK_PARAMS = /\b(input|data|param|value|body|content|text|name|id|user|email|password|token|key|secret|header|cookie)\b/i;

export function detectParameterRiskBoost(text: string): number {
  if (!text) return 0;
  if (HIGH_RISK_PARAMS.test(text)) return 1.0;
  if (MEDIUM_RISK_PARAMS.test(text)) return 0.5;
  return 0;
}

/** Shared risk scoring used by all tasks. */
export function scoreFindingMetadata(input: {
  severity?: string;
  likelihood?: string;
  impact?: string;
  subcategory?: string[];
  cwe?: string[];
  parameterRiskBoost?: number;
}): number {
  const severity = SEVERITY_SCORE[(input.severity ?? "INFO").toUpperCase()] ?? 1;
  const likelihood = LIKELIHOOD_SCORE[(input.likelihood ?? "LOW").toUpperCase()] ?? 1;
  const impact = IMPACT_SCORE[(input.impact ?? "LOW").toUpperCase()] ?? 1;
  const subcategories = input.subcategory ?? ["audit"];
  const subcategory = Math.max(...subcategories.map((s) => SUBCATEGORY_SCORE[s] ?? 0), 1);

  let baseScore = severity * likelihood * impact * subcategory;

  // Apply CWE frequency multiplier (highest matching)
  if (input.cwe && input.cwe.length > 0) {
    let maxMultiplier = 1.0;
    for (const cweId of input.cwe) {
      const normalized = cweId.replace(/^CWE-/i, "").trim();
      const multiplier = CWE_FREQUENCY_MULTIPLIER[normalized];
      if (multiplier !== undefined && multiplier > maxMultiplier) {
        maxMultiplier = multiplier;
      }
    }
    baseScore *= maxMultiplier;
  }

  // Apply parameter risk boost (additive)
  if (input.parameterRiskBoost && input.parameterRiskBoost > 0) {
    baseScore += input.parameterRiskBoost * 10; // Scale boost to score range
  }

  return baseScore;
}

/**
 * Secret-scan detector pack.
 *
 * Each detector is a regex + metadata. Detectors that have a higher
 * false-positive risk (e.g. generic OpenAI-shaped keys) carry an
 * `entropyThreshold`; matches whose Shannon entropy falls below the
 * threshold are dropped.
 *
 * Detectors are intentionally curated — we'd rather miss an obscure
 * vendor's token than spam operators with FPs. New detectors should
 * include a fixture line in `tests/fixtures/secret-scan/` that exercises
 * both the positive and (for entropy-gated rules) the negative case.
 */

export interface SecretDetector {
  /** Stable rule id used in the finding's `ruleId`. */
  readonly id: string;
  /** Short human-readable name (rendered in the summary). */
  readonly name: string;
  /** Severity used on Finding.severity (`ERROR`/`WARNING`/`INFO`). */
  readonly severity: "ERROR" | "WARNING" | "INFO";
  /** Single-line regex; `g` flag is enforced when scanning. */
  readonly pattern: RegExp;
  /**
   * Optional minimum Shannon entropy (per-character bits) of the captured
   * group. Useful for high-FP rules ("looks like a token but might be
   * a hash digest"). Undefined → no entropy gate.
   */
  readonly entropyThreshold?: number;
  /** CWE associated with the leak (defaults to CWE-798 hard-coded creds). */
  readonly cwe?: string;
  /** One-line description shown in the finding message. */
  readonly description: string;
}

/**
 * Compute the per-character Shannon entropy (bits) of a string.
 * Used by entropy-gated detectors to suppress matches that look like
 * structured data (e.g. base64 hashes) rather than secrets.
 */
export function shannonEntropy(input: string): number {
  if (input.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of input) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Redact a secret for safe inclusion in a Finding's `evidence` field.
 * Keeps the first 4 characters as a hint for the operator (so they can
 * recognise which token leaked) and replaces the rest with `***`.
 */
export function redactSecret(secret: string): string {
  if (secret.length <= 4) return "***";
  return `${secret.slice(0, 4)}${"*".repeat(Math.min(8, secret.length - 4))}`;
}

/**
 * The default detector pack. Order is significant for performance only —
 * the scanner does not stop on first match.
 */
export const DEFAULT_DETECTORS: ReadonlyArray<SecretDetector> = [
  {
    id: "aws-access-key",
    name: "AWS Access Key ID",
    severity: "ERROR",
    pattern: /\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b/g,
    cwe: "CWE-798",
    description: "AWS access key ID committed to source.",
  },
  {
    id: "aws-secret-key",
    name: "AWS Secret Access Key",
    severity: "ERROR",
    pattern:
      /(?:aws[_-]?secret(?:[_-]?access)?[_-]?key|aws_secret)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    entropyThreshold: 4.0,
    cwe: "CWE-798",
    description: "AWS secret access key candidate (40-char base64).",
  },
  {
    id: "github-pat",
    name: "GitHub Personal Access Token",
    severity: "ERROR",
    pattern: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/g,
    cwe: "CWE-798",
    description: "GitHub fine-grained or classic personal access token.",
  },
  {
    id: "slack-token",
    name: "Slack Token",
    severity: "ERROR",
    pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
    cwe: "CWE-798",
    description: "Slack bot/user/app token.",
  },
  {
    id: "stripe-live-key",
    name: "Stripe Live Key",
    severity: "ERROR",
    pattern: /\b(sk|pk|rk)_live_[A-Za-z0-9]{24,}\b/g,
    cwe: "CWE-798",
    description: "Stripe live API key (production credentials).",
  },
  {
    id: "stripe-test-key",
    name: "Stripe Test Key",
    severity: "WARNING",
    pattern: /\b(sk|pk|rk)_test_[A-Za-z0-9]{24,}\b/g,
    cwe: "CWE-798",
    description: "Stripe test API key — still a leak even if low-impact.",
  },
  {
    id: "google-api-key",
    name: "Google API Key",
    severity: "ERROR",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    cwe: "CWE-798",
    description: "Google Cloud / Maps / Firebase API key.",
  },
  {
    id: "anthropic-api-key",
    name: "Anthropic API Key",
    severity: "ERROR",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    cwe: "CWE-798",
    description: "Anthropic API key.",
  },
  {
    id: "openai-api-key",
    name: "OpenAI API Key",
    severity: "ERROR",
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g,
    entropyThreshold: 3.5,
    cwe: "CWE-798",
    description: "OpenAI-style API key (sk-… or sk-proj-…).",
  },
  {
    id: "jwt-token",
    name: "JSON Web Token",
    severity: "WARNING",
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g,
    cwe: "CWE-522",
    description: "JWT-shaped token; verify it isn't a long-lived credential.",
  },
  {
    id: "pem-private-key",
    name: "PEM Private Key",
    severity: "ERROR",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    cwe: "CWE-798",
    description: "PEM-encoded private key block.",
  },
  {
    id: "generic-secret-assignment",
    name: "Generic Secret Assignment",
    severity: "WARNING",
    // password / passwd / api_key / api-key / secret / token = "..." with
    // a 16+ char value. Entropy gated to suppress placeholders like
    // "password = changeme".
    pattern:
      /\b(?:password|passwd|api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]([A-Za-z0-9!@#$%^&*_+/=-]{16,})['"]/gi,
    entropyThreshold: 3.5,
    cwe: "CWE-798",
    description: "Likely-credential assignment with a high-entropy value.",
  },
];

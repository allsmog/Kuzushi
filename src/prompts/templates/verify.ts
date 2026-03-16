/**
 * Verification prompt templates — template-string equivalents of the prompts
 * currently built via string concatenation in src/verify.ts.
 *
 * These templates use {{ variable }} syntax and are rendered via
 * renderTemplate() from ../template.ts.
 *
 * NOTE: These are NOT yet wired into the live verification pipeline.
 * They exist as a foundation for gradual migration.
 */

/**
 * Single-finding verification prompt template.
 *
 * Expected context shape: VerifyTemplateContext
 *
 * Equivalent to: buildVerificationPrompt() in src/verify.ts
 *
 * Note: The bypass knowledge section is injected dynamically and is not
 * part of the static template. When migrating, the caller should prepend
 * any bypass section before the "## Finding" heading.
 */
export const VERIFY_TEMPLATE = `You are a senior exploit engineer and penetration tester. Your job is to determine if a
reported vulnerability is concretely exploitable in practice — not just theoretically possible.
You think like an attacker: you craft payloads, trace execution paths, and identify the exact
conditions needed for exploitation.

## Finding
Repo: {{ repoName }}
Scanner: {{ finding.scanner }}
Rule: {{ finding.ruleId }}
File: {{ finding.filePath }}:{{ finding.startLine }}
Severity: {{ finding.severity }}
CWE: {{ finding.cweDisplay }}
Message: {{ finding.message }}
Fingerprint: {{ finding.fingerprint }}

## Prior triage assessment
Verdict: {{ triage.verdict }}
Confidence: {{ triage.confidence }}
Rationale: {{ triage.rationale }}
Verification steps: {{ triage.verificationStepsDisplay }}

## Verification instructions
1. Trace attacker-controlled input sources to vulnerable sinks through real call paths.
2. Identify sanitization, encoding, validation, authz, feature flags, and reachability constraints.
3. Decide whether the issue is exploitable with a concrete input payload under realistic conditions.
4. If exploitable, provide a concise PoC payload and attack vector.
5. If not exploitable, explain precisely why (for example: sanitization, validation, unreachable path).
6. List any preconditions required to reproduce impact.

## Output requirements
Return ONLY a JSON object with keys:
fingerprint, exploitable(boolean), poc_payload(string|null), poc_description(string),
attack_vector(string|null), preconditions(string[]), confidence(0..1),
proof_level(1-4, optional), proof_verdict(exploited|blocked_by_security|out_of_scope|false_positive, optional),
bypass_attempts(string[], optional)`;

/**
 * Architectural / threat-model finding verification template.
 *
 * Used when finding.filePath === "." — the finding is not tied to a specific
 * file and requires broader investigation.
 *
 * Expected context shape: VerifyTemplateContext
 */
export const VERIFY_ARCHITECTURAL_TEMPLATE = `You are a senior exploit engineer and penetration tester. Your job is to determine if a
reported vulnerability is concretely exploitable in practice — not just theoretically possible.
You think like an attacker: you craft payloads, trace execution paths, and identify the exact
conditions needed for exploitation.

## Finding
Repo: {{ repoName }}
Scanner: {{ finding.scanner }}
Rule: {{ finding.ruleId }}
File: {{ finding.filePath }}:{{ finding.startLine }}
Severity: {{ finding.severity }}
CWE: {{ finding.cweDisplay }}
Message: {{ finding.message }}
Fingerprint: {{ finding.fingerprint }}

## Prior triage assessment
Verdict: {{ triage.verdict }}
Confidence: {{ triage.confidence }}
Rationale: {{ triage.rationale }}
Verification steps: {{ triage.verificationStepsDisplay }}

## Verification instructions
This is an architectural/threat-model finding without a specific file. Use Glob and Grep to identify relevant source files.
1. Verify the described threat is realistic given the actual system architecture and code.
2. Check whether existing mitigations (auth, validation, rate limiting, encryption) address the threat.
3. Decide whether the issue is concretely exploitable under realistic conditions.
4. If exploitable, describe a concrete attack vector and payload.
5. If not exploitable, explain precisely which mitigations prevent it.
6. List any preconditions required to reproduce impact.

## Output requirements
Return ONLY a JSON object with keys:
fingerprint, exploitable(boolean), poc_payload(string|null), poc_description(string),
attack_vector(string|null), preconditions(string[]), confidence(0..1),
proof_level(1-4, optional), proof_verdict(exploited|blocked_by_security|out_of_scope|false_positive, optional),
bypass_attempts(string[], optional)`;

/**
 * Batch verification prompt header template.
 *
 * Expected context shape: { repoName: string; findingCount: number }
 *
 * Equivalent to: buildBatchVerificationPrompt() header in src/verify.ts
 */
export const BATCH_VERIFY_HEADER_TEMPLATE = `You are a senior exploit engineer and penetration tester. Your job is to determine if
reported vulnerabilities are concretely exploitable in practice — not just theoretically possible.
You think like an attacker: you craft payloads, trace execution paths, and identify the exact
conditions needed for exploitation.

Investigate ALL of the following findings and determine exploitability for each.

Repo: {{ repoName }}

## Findings ({{ findingCount }} total)`;

/**
 * Per-finding section template for batch verification.
 *
 * Expected context shape: VerifyTemplateContext plus { findingIndex: number }
 */
export const BATCH_VERIFY_FINDING_TEMPLATE = `### Finding {{ findingIndex }}
Scanner: {{ finding.scanner }}
Rule: {{ finding.ruleId }}
File: {{ finding.filePath }}:{{ finding.startLine }}
Severity: {{ finding.severity }}
CWE: {{ finding.cweDisplay }}
Message: {{ finding.message }}
Fingerprint: {{ finding.fingerprint }}
Triage verdict: {{ triage.verdict }}
Triage confidence: {{ triage.confidence }}
Triage rationale: {{ triage.rationale }}
Triage verification steps: {{ triage.verificationStepsDisplay }}`;

/**
 * Batch verification prompt footer — instructions and output format.
 *
 * Expected context shape: { findingCount: number }
 */
export const BATCH_VERIFY_FOOTER_TEMPLATE = `## Verification instructions
For each finding:
1. Trace attacker-controlled input sources to vulnerable sinks through real call paths.
2. Identify sanitization, encoding, validation, authz, feature flags, and reachability constraints.
3. Decide whether the issue is exploitable with a concrete input payload under realistic conditions.
4. If exploitable, provide a concise PoC payload and attack vector.
5. If not exploitable, explain precisely why.
6. List any preconditions required to reproduce impact.

## Output requirements
Return ONLY a JSON object with a "results" array. Each element MUST have:
fingerprint, exploitable(boolean), poc_payload(string|null), poc_description(string),
attack_vector(string|null), preconditions(string[]), confidence(0..1),
proof_level(1-4, optional), proof_verdict(optional), bypass_attempts(string[], optional)

You must return exactly {{ findingCount }} results, one per finding, using the exact fingerprints listed above.`;

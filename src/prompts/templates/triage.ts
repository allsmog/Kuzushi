/**
 * Triage prompt templates — template-string equivalents of the prompts
 * currently built via string concatenation in src/triage.ts.
 *
 * These templates use {{ variable }} syntax and are rendered via
 * renderTemplate() from ../template.ts.
 *
 * NOTE: These are NOT yet wired into the live triage pipeline.
 * They exist as a foundation for gradual migration.
 */

/**
 * Single-finding triage prompt template.
 *
 * Expected context shape: TriageTemplateContext
 *
 * Equivalent to: buildDefaultTriageAgentConfig() in src/triage.ts
 */
export const TRIAGE_TEMPLATE = `You are a skeptical senior security engineer performing triage. Assume every finding is a
false positive until you can prove otherwise with concrete evidence from the code. You have
seen thousands of scanner findings and know that 60-80% are false positives due to missing
context about middleware, framework protections, and sanitization.

Use available repo tools to investigate whether this finding is a true or false positive.

## Finding
Repo: {{ repoName }}
Scanner: {{ finding.taskId }}
Rule: {{ finding.ruleId }}
File: {{ finding.filePath }}:{{ finding.startLine }}
Severity: {{ finding.severity }}
Scanner Confidence: {{ finding.scannerConfidence }}
Likelihood: {{ finding.likelihood }}
Impact: {{ finding.impact }}
CWE: {{ finding.cweDisplay }}
Message: {{ finding.message }}
Evidence: {{ finding.evidence }}
Fingerprint: {{ finding.fingerprint }}

## Investigation instructions
1. Read the flagged file and surrounding code.
2. Trace dataflow to source/sink across call boundaries.
3. Use Grep/Glob to locate sanitization, validation, and guards.
4. Validate reachability and realistic attacker control.
5. Use GetCallers to find who calls the vulnerable function and trace attacker-controlled input.
6. Use GetCallees to understand what downstream functions the vulnerable code invokes.
7. Use GetFunctionBody to inspect specific sanitizers, validators, or middleware functions.
8. Decide tp/fp/by_design/needs_review using the confidence escalation protocol below.

## Output requirements
Return ONLY a JSON object with:
fingerprint, verdict(tp|fp|by_design|needs_review), confidence(0..1), rationale, verification_steps(array), fix_patch(string|null),
evidence_trail(optional array of {level: string, evidence: string})

Use verdict "by_design" when the code pattern is technically accurate but is an intentional architectural decision
for the application's purpose (e.g., missing authentication in a pentest tool, permissive TLS in a debugging proxy).
Reserve "tp" for actual bugs and vulnerabilities that harm the application's users or operators.`;

/**
 * Batch triage prompt template — header section (per-finding sections
 * are appended dynamically because their count varies).
 *
 * Expected context shape: TriageTemplateContext with findingCount set
 *
 * Equivalent to: buildBatchTriagePrompt() header in src/triage.ts
 */
export const BATCH_TRIAGE_HEADER_TEMPLATE = `You are a skeptical senior security engineer performing batch triage. Assume each finding is a
false positive until you can prove otherwise with concrete code evidence. Most scanner findings
are FPs due to missing context about middleware, framework protections, and sanitization.

Investigate ALL of the following findings and determine if each is a true positive, false positive, or needs review.

Repo: {{ repoName }}

## Findings ({{ findingCount }} total)`;

/**
 * Per-finding section template for batch triage.
 *
 * Expected context shape: TriageTemplateContext (one finding)
 * plus { findingIndex: number }
 */
export const BATCH_TRIAGE_FINDING_TEMPLATE = `### Finding {{ findingIndex }}
Scanner: {{ finding.taskId }}
Rule: {{ finding.ruleId }}
File: {{ finding.filePath }}:{{ finding.startLine }}
Severity: {{ finding.severity }}
Scanner Confidence: {{ finding.scannerConfidence }}
Likelihood: {{ finding.likelihood }}
Impact: {{ finding.impact }}
CWE: {{ finding.cweDisplay }}
Message: {{ finding.message }}
Evidence: {{ finding.evidence }}
Fingerprint: {{ finding.fingerprint }}`;

/**
 * Batch triage prompt footer — investigation instructions and output requirements.
 *
 * Expected context shape: { findingCount: number }
 */
export const BATCH_TRIAGE_FOOTER_TEMPLATE = `## Investigation instructions
1. Read the flagged files and surrounding code.
2. Trace dataflow from source to sink across call boundaries.
3. Use Grep/Glob to locate sanitization, validation, and guards.
4. Validate reachability and realistic attacker control.
5. Decide tp/fp/by_design/needs_review per finding using the confidence escalation protocol below.

## Output requirements
Return ONLY a JSON object with a "results" array. Each element MUST have:
fingerprint, verdict(tp|fp|by_design|needs_review), confidence(0..1), rationale, verification_steps(array of strings), fix_patch(string|null)

You must return exactly {{ findingCount }} results, one per finding, using the exact fingerprints listed above.`;

/**
 * Unified batch triage prompt template using {% for %} loop.
 *
 * Expected context shape: BatchTriageTemplateContext
 *
 * Equivalent to: buildBatchTriagePrompt() in src/triage.ts
 */
export const BATCH_TRIAGE_TEMPLATE = `You are a skeptical senior security engineer performing batch triage. Assume each finding is a
false positive until you can prove otherwise with concrete code evidence. Most scanner findings
are FPs due to missing context about middleware, framework protections, and sanitization.

Investigate ALL of the following findings and determine if each is a true positive, false positive, or needs review.

Repo: {{ repoName }}

## Findings ({{ findingCount }} total)

{% for finding in findings %}### Finding {{ loop.index }}
Scanner: {{ finding.taskId }}
Rule: {{ finding.ruleId }}
File: {{ finding.filePath }}:{{ finding.startLine }}
Severity: {{ finding.severity }}
Scanner Confidence: {{ finding.scannerConfidence }}
Likelihood: {{ finding.likelihood }}
Impact: {{ finding.impact }}
CWE: {{ finding.cweDisplay }}
Message: {{ finding.message }}
Evidence: {{ finding.evidence }}
Fingerprint: {{ finding.fingerprint }}

{% endfor %}## Investigation instructions
1. Read the flagged files and surrounding code.
2. Trace dataflow from source to sink across call boundaries.
3. Use Grep/Glob to locate sanitization, validation, and guards.
4. Validate reachability and realistic attacker control.
5. Decide tp/fp/by_design/needs_review per finding using the confidence escalation protocol below.

## Output requirements
Return ONLY a JSON object with a "results" array. Each element MUST have:
fingerprint, verdict(tp|fp|by_design|needs_review), confidence(0..1), rationale, verification_steps(array of strings), fix_patch(string|null)

You must return exactly {{ findingCount }} results, one per finding, using the exact fingerprints listed above.`;

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
Return ONLY a JSON object. Every field below is REQUIRED for tp and needs_review verdicts. For fp and by_design, only the core fields are required.

Core fields (ALWAYS required):
- fingerprint (string)
- title (string, 5-12 words describing the vulnerability, not the rule)
- display_severity ("critical"|"high"|"medium"|"low")
- verdict ("tp"|"fp"|"by_design"|"needs_review")
- confidence (0..1)
- rationale (string)
- verification_steps (array of strings — what you checked)
- fix_patch (string|null)

Extended fields (REQUIRED for tp and needs_review, optional for fp/by_design):
- attack_narrative (string) — a 2-3 sentence Alice-and-Bob style attack scenario. Use concrete actors (e.g. "An attacker controlling repo content", "A network attacker on the local network"). Describe who, what action, and what they gain.
- sink_function (string|null) — the dangerous function/API that data flows into (e.g. "execSync", "eval", "db.query")
- code_citations (array of {file_path, start_line, end_line, snippet, description}) — cite EVERY code location you investigated with the actual code snippet and why it matters. Include at least 2 citations for tp findings.
- attack_path ({chain: string[], narrative: string, likelihood_reasoning: string, impact_reasoning: string}) — the step-by-step attack path from entry to impact as an ordered chain (e.g. ["Operator runs scan on untrusted repo", "Shell creates AgentSession with Bash in allowedTools", "LLM invokes Bash tool via prompt injection", "bash -c executes on host"]). Include narrative explanation and EXPLICIT reasoning for your likelihood and impact assessments.
- assumptions (string[]) — list ALL assumptions underlying your assessment (e.g. "Operator runs tool on attacker-controlled repository", "Default configuration is used without custom tool policies").
- controls (array of {name, description, file_path?}) — identify ALL existing security controls and defenses you found, even partial ones (e.g. {name: "Tool policy framework", description: "Supports allow/deny layers but Bash is allowed by default", file_path: "src/prompts/tool-policy.ts"}).
- blindspots (string[]) — list what your analysis could NOT verify (e.g. "No runtime PoC executed", "Did not verify operator deployment configuration").
- source_threat_ids (string[]) — if threat model context is provided above, reference the threat IDs (e.g. ["T-01", "T-03"]) this finding relates to.

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
fingerprint, title(5-12 words), display_severity(critical|high|medium|low), verdict(tp|fp|by_design|needs_review), confidence(0..1), rationale, verification_steps(array of strings), fix_patch(string|null)

You must return exactly {{ findingCount }} results, one per finding, using the exact fingerprints listed above.

For tp and needs_review findings, you MUST also include:
attack_narrative(string), code_citations(array of {file_path, start_line, end_line, snippet, description}),
attack_path({chain, narrative, likelihood_reasoning, impact_reasoning}),
assumptions(string[]), controls(array of {name, description, file_path?}), blindspots(string[]),
source_threat_ids(string[], if threat model context provided).`;

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
fingerprint, title(5-12 words), display_severity(critical|high|medium|low), verdict(tp|fp|by_design|needs_review), confidence(0..1), rationale, verification_steps(array of strings), fix_patch(string|null)

You must return exactly {{ findingCount }} results, one per finding, using the exact fingerprints listed above.

For tp and needs_review findings, you MUST also include:
attack_narrative(string), code_citations(array of {file_path, start_line, end_line, snippet, description}),
attack_path({chain, narrative, likelihood_reasoning, impact_reasoning}),
assumptions(string[]), controls(array of {name, description, file_path?}), blindspots(string[]),
source_threat_ids(string[], if threat model context provided).`;

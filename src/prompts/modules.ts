import type { RepoContext } from "../types.js";

/**
 * Composable prompt modules — pure functions returning prompt sections.
 * Extracted from triage.ts, verify.ts, and detection task files to enable
 * reuse without copy-paste.
 */

export interface AntiHallucinationOpts {
  /** Additional anti-hallucination constraints beyond the defaults. */
  extra?: string[];
}

/**
 * Standard anti-hallucination constraints shared across all agentic detection tasks.
 */
export function antiHallucinationModule(opts?: AntiHallucinationOpts): string {
  const lines = [
    "## Anti-hallucination constraints",
    "- Only report concrete issues you can verify in code. Do not report secure patterns.",
    "- Do NOT infer or speculate about code you haven't read.",
    "- If a library is used correctly per its documentation, do not flag it.",
    "- Confidence must reflect your actual certainty: HIGH only if the issue is unambiguous.",
  ];

  if (opts?.extra) {
    for (const line of opts.extra) {
      lines.push(`- ${line}`);
    }
  }

  return lines.join("\n");
}

/**
 * Confidence escalation protocol — defines the evidence ladder from 0.1 to 1.0.
 * Context-specific variants for triage vs. verification vs. detection.
 */
export function confidenceEscalationModule(
  context: "triage" | "verification" | "detection",
): string {
  const header = "## Confidence Escalation Protocol";
  const preamble = "Start at 0.1. Escalate only with evidence:";

  if (context === "triage") {
    return [
      header,
      preamble,
      "- 0.1-0.3: Read flagged code but haven't traced full path",
      "- 0.3-0.5: Traced source-to-sink but haven't verified guards",
      "- 0.5-0.7: Verified guards absent AND input is attacker-controlled",
      "- 0.7-0.9: Full path verified with concrete exploit scenario",
      "- 0.9-1.0: Verified exploitable with specific payload",
      "Your rationale MUST cite the evidence that justifies your confidence level.",
    ].join("\n");
  }

  if (context === "verification") {
    return [
      header,
      preamble,
      "- 0.1-0.3: Identified theoretical weakness only",
      "- 0.3-0.5: Partial bypass achieved but blocked by defense",
      "- 0.5-0.7: Defense bypass feasible with specific technique",
      "- 0.7-0.9: Full bypass confirmed with concrete payload",
      "- 0.9-1.0: Complete exploitation demonstrated with account takeover",
    ].join("\n");
  }

  // detection
  return [
    header,
    preamble,
    "- 0.1-0.3: Pattern matched but haven't verified context",
    "- 0.3-0.5: Verified usage but haven't confirmed exploitability",
    "- 0.5-0.7: Confirmed insecure usage with no compensating controls",
    "- 0.7-0.9: Verified exploitable with concrete attack scenario",
    "- 0.9-1.0: Demonstrated exploitation with specific payload",
  ].join("\n");
}

/**
 * Framework awareness module — adapts to detected frameworks in repo context.
 */
export function frameworkAwarenessModule(repoContext?: RepoContext): string {
  if (!repoContext?.frameworks.length) {
    return "";
  }

  const lines = [
    "## Framework Awareness",
    `Detected frameworks: ${repoContext.frameworks.join(", ")}`,
    `- Account for framework defaults: ${repoContext.frameworks.join(", ")} may provide secure defaults.`,
    "- Verify whether the framework's built-in protections are active before flagging.",
    "- Check framework-specific configuration that may enable or disable security features.",
  ];

  return lines.join("\n");
}

/**
 * Common false-dismissal patterns — rationalizations that should not be
 * accepted as FP evidence without further investigation.
 */
export function falseDismissalModule(): string {
  return [
    "## Common False-Dismissal Patterns",
    "Do NOT dismiss a finding based solely on these rationalizations:",
    '"The WAF will catch it" — WAFs are bypassable; test the application logic',
    '"We use parameterized queries" — check for ORM misuse, stored procedures with dynamic SQL, and second-order injection',
    '"The framework handles XSS" — template engines have raw output modes, JS contexts bypass HTML encoding, DOM XSS is client-side',
    '"File uploads are safe because we check the extension" — null bytes, double extensions, parser discrepancies bypass extension checks',
    '"We validate on the frontend" — client-side validation is UX, not security',
    '"It\'s internal, auth doesn\'t matter" — internal apps get compromised via SSRF and lateral movement',
    '"Low severity, not worth flagging" — low-severity findings chain into critical attack paths',
    "If your FP rationale matches any of these patterns, re-investigate before concluding.",
  ].join("\n");
}

/**
 * Bypass exhaustion protocol — required techniques to attempt before
 * classifying a finding as not-exploitable.
 */
export function bypassExhaustionModule(): string {
  return [
    "## Bypass Exhaustion Protocol",
    "Before classifying as not-exploitable, you MUST try:",
    "- Direct exploitation with obvious payload",
    "- Parameter pollution / type juggling",
    "- Encoding bypass (URL, Unicode, double-encoding)",
    "- Race condition / timing attack",
    "- Chained exploitation with another weakness",
    "Document each attempt and its result in bypass_attempts.",
  ].join("\n");
}

/**
 * Proof level framework — classifies verification depth from theoretical
 * to full exploitation.
 */
export function proofLevelModule(): string {
  return [
    "## Proof Level Framework",
    "Classify your findings using these proof levels:",
    "Level 1: Theoretical weakness identified",
    "Level 2: Partial bypass achieved (e.g., UI access without function)",
    "Level 3: Full bypass confirmed (unauthorized protected functionality)",
    "Level 4: Account takeover demonstrated",
    "",
    "## Verdicts",
    "EXPLOITED: Level 3+ with concrete evidence",
    "BLOCKED_BY_SECURITY: Valid vuln but blocked by WAF/defense (document what blocks it)",
    "OUT_OF_SCOPE: Requires internal/physical access",
    "FALSE_POSITIVE: Exhausted all bypass techniques, confirmed safe",
  ].join("\n");
}

/**
 * Knowledge injection module — formats knowledge registry query results
 * for prompt injection. Returns empty string if no results.
 */
export function knowledgeInjectionModule(
  formattedSections: string[],
): string {
  if (formattedSections.length === 0) {
    return "";
  }

  return [
    "## Domain Knowledge",
    ...formattedSections,
  ].join("\n");
}

/**
 * Evidence chain module — instructs the agent to produce per-step evidence
 * confidences for fine-grained calibration.
 */
export function evidenceChainModule(): string {
  return [
    "## Evidence Chain (Fine-Grained Confidence)",
    "In addition to your overall verdict, report an evidence_chain array in your JSON output.",
    "Each element represents one investigation step with its own confidence score.",
    "",
    "Supported step_type values:",
    "- source-reachability: Is the input attacker-controllable?",
    "- sink-danger: Is the sink security-critical?",
    "- sanitization-check: Were guards/sanitizers verified?",
    "- config-review: Were security configs checked?",
    "- dataflow-trace: Was full source→sink flow traced?",
    "- exploit-feasibility: Is a concrete exploit possible?",
    "- framework-protection: Do framework defaults protect?",
    "",
    "Example evidence_chain entry:",
    '{ "step_type": "source-reachability", "description": "Traced req.query.id to SQL query", "confidence": 0.8, "evidence": "User input flows from line 12 to query at line 45 without validation" }',
    "",
    "Include only steps you actually investigated. Each step confidence should reflect",
    "your certainty for THAT specific aspect, independent of other steps.",
  ].join("\n");
}

/**
 * Compose multiple prompt module outputs into a single prompt string.
 * Filters out empty strings and joins with double newlines.
 */
export function composePromptModules(...sections: string[]): string {
  return sections.filter(Boolean).join("\n\n");
}

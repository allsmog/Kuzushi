//! Reusable prompt spine blocks shared by every finding-producing agent prompt.
//!
//! These constants restore the legacy attacker methodology, confidence
//! calibration, empty-result legitimacy, and output-contract discipline into
//! the active Rust prompts. Prompt builders concatenate the relevant blocks
//! rather than inlining their own variants.

/// Attacker + skeptical-reviewer methodology (map surface, trace source→sink,
/// verify guards before reporting).
pub const ATTACKER_METHODOLOGY: &str =
    "You think like an attacker and a skeptical security reviewer. You map attack surface, \
trace data flow from source to sink, and verify exploitability before reporting. Most \
static signals are false positives, so every reported finding must be justified by cited \
code evidence.

Method:
1. Map candidate surfaces: request handlers, auth and middleware, deserializers, \
   template/render code, filesystem access, process execution, database/query code, \
   redirects, outbound HTTP, dependency/plugin loading, background jobs, and privilege \
   boundaries.
2. For each candidate, identify the attacker-controlled source and the concrete sink. \
   Trace the path across call boundaries when possible.
3. Inspect every intervening guard: sanitization, validation, allowlists, encoding, \
   type/length constraints, authn/authz, feature flags, framework defaults, router or \
   middleware checks, and centralized upstream validators.
4. Report only findings where the source, sink, path, and missing/bypassed guard are \
   grounded in code evidence. If you cannot inspect a critical link, emit a candidate \
   or `needs_review`, not a confirmed finding.";

/// Confidence calibration by evidence, requesting a band rather than a raw float.
pub const CONFIDENCE_CALIBRATION: &str = "Assign confidence by evidence, not by how sure you feel:

- high: traced a specific attacker-controlled source to an unguarded sink and inspected \
  every intervening guard, OR found a validator/guard that provably defeats all attacker- \
  controlled values. Cite the decisive file:line evidence.
- medium: the pattern is real and at least one path appears unguarded, but end-to-end \
  reachability, attacker control, or a suspected guard could not be fully inspected.
- low: signals are mixed, the relevant code was not reached, or the conclusion depends \
  on assumptions. Low-confidence items should normally surface as `needs_review` or be \
  omitted by finding producers.

Your rationale must cite the file:line evidence that justifies the confidence band. Return \
a confidence band (high/medium/low), not an invented numeric probability.";

/// Numbered do-not-report exclusion rules. Complements FALSE_POSITIVE_TAXONOMY:
/// the taxonomy governs how to judge evidence; these rules exclude whole
/// finding shapes regardless of evidence quality.
pub const EXCLUSION_RULES: &str = "DO NOT REPORT, even when technically accurate:
1. Volumetric denial of service or missing rate limiting (infrastructure-layer concerns). \
   EXCEPTIONS that ARE valid findings: ReDoS, algorithmic complexity, hash-collision DoS, \
   and unbounded recursion or allocation triggered by specific crafted input.
2. Test-only code, dead code, example/fixture code, or crashes with no security impact.
3. Behavior that is the intended design of the software (compression middleware, a \
   backward-compatible weak algorithm offered alongside a strong one for migration).
4. Memory-safety concerns in memory-safe-language code — flag only unsafe/FFI blocks or \
   safe APIs wrapping unsound unsafe internals.
5. SSRF where the attacker controls only the request path — the finding requires control \
   of the host or protocol.
6. User input flowing into an AI/LLM prompt (prompt injection is not a code vulnerability \
   in the scanned target).
7. Path traversal inside object-storage keys (S3, GCS) where `../` does not escape a \
   trust boundary.
8. Trusted operator inputs used as the attack vector (environment variables, CLI flags \
   set by the operator) — unless the stated environment marks them attacker-controlled.
9. Client-side code flagged for server-side vulnerability classes (SSRF, path traversal, \
   missing auth — the server is responsible).
10. Outdated third-party dependency versions (managed by a separate process).
11. Weak randomness or hardcoded defaults used for non-security purposes (jitter, \
    shuffling, load balancing, dev-only fallbacks replaced from secure sources in \
    production).
12. Low-impact nuisance issues: log spoofing, CSRF on logout, self-XSS where the user is \
    sole source and sole consumer, and best-practice violations without a concrete \
    exploit path.
When an exclusion rule drives a rejection or omission, cite the rule number in the \
rationale.";

/// Derive severity mechanically from attacker preconditions instead of the
/// vulnerability category. Vocabulary matches the closed `Precondition` enum
/// in `findings::ingest_contract` so the write-time ceiling can be enforced
/// in code.
pub const SEVERITY_FROM_PRECONDITIONS: &str =
    "Derive severity from exploitability, not from the vulnerability category.

Before assigning severity, enumerate every precondition an attacker must satisfy \
(auth state, configuration, prior requests, race windows, attacker position). Name the \
weakest credible attacker position using exactly one of: unauth-network, protected-host, \
cross-tenant, paired-peer, authed-role, local-uid, mitm, insider, supply-chain, physical.

Ceilings: unauth-network / cross-tenant / protected-host findings may reach critical; \
paired-peer / authed-role / local-uid / mitm / insider / supply-chain cap at high; \
physical caps at medium. Within the ceiling, more preconditions mean lower severity: \
zero preconditions justifies the ceiling itself; one or two justify one step below; \
three or more (or no demonstrated attack path) justify at most medium.

Cross-check before emitting: if the precondition list has three or more entries, \
critical or high is almost certainly wrong. If the code is a test, example, or \
debug-only path, do not report it at all (exclusion rule 2). When torn between two \
levels, choose the lower — an inflated severity costs reviewer trust.";

/// Coverage must be exhaustive even though reporting stays evidence-gated.
pub const EXHAUSTIVENESS: &str =
    "Be exhaustive in COVERAGE while staying evidence-gated in REPORTING. Do not stop at \
the first finding: a single file often contains multiple independent vulnerabilities, and \
an assigned scope usually contains several. After recording a finding, continue analyzing \
the remaining files in scope; one finding is a floor, not a goal. If the scope is dense \
and the output budget nears its limit, prioritize the highest-severity findings and state \
how many lower-severity candidates were left unreported so the operator can re-scope. \
Exhaustive coverage never lowers the evidence bar: every reported finding still requires \
cited code evidence.";

/// Empty findings are a correct, valued outcome.
pub const EMPTY_FINDINGS_OK: &str =
    "Reporting zero findings is a correct, valued outcome. Return {\"findings\":[]} rather than \
lowering the evidence bar. False negatives are preferable to fabricated positives.";

/// Output-contract reminder: return only the enforced structured output.
pub const OUTPUT_CONTRACT: &str =
    "Output conforms to the enforced structured-output schema. Return only that structured \
output. Do not include markdown fences, prose, tool-call preambles, or schema text.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn methodology_covers_source_sink_and_guards() {
        assert!(ATTACKER_METHODOLOGY.contains("source to sink"));
        assert!(ATTACKER_METHODOLOGY.contains("intervening guard"));
    }

    #[test]
    fn calibration_requests_a_band_not_a_float() {
        assert!(CONFIDENCE_CALIBRATION.contains("confidence band"));
        assert!(CONFIDENCE_CALIBRATION.contains("not an invented numeric probability"));
    }

    #[test]
    fn empty_findings_line_is_present() {
        assert!(EMPTY_FINDINGS_OK.contains("{\"findings\":[]}"));
    }

    #[test]
    fn exclusion_rules_number_twelve_and_keep_the_redos_carve_out() {
        assert!(EXCLUSION_RULES.contains("12."));
        assert!(EXCLUSION_RULES.contains("ReDoS"));
        assert!(EXCLUSION_RULES.contains("cite the rule number"));
    }

    #[test]
    fn severity_block_uses_the_closed_precondition_vocabulary() {
        for token in [
            "unauth-network",
            "protected-host",
            "cross-tenant",
            "paired-peer",
            "authed-role",
            "local-uid",
            "mitm",
            "insider",
            "supply-chain",
            "physical",
        ] {
            assert!(
                SEVERITY_FROM_PRECONDITIONS.contains(token),
                "missing precondition token {token}"
            );
        }
        assert!(SEVERITY_FROM_PRECONDITIONS.contains("three or more"));
    }

    #[test]
    fn exhaustiveness_keeps_the_evidence_bar() {
        assert!(EXHAUSTIVENESS.contains("one finding is a floor"));
        assert!(EXHAUSTIVENESS.contains("never lowers the evidence bar"));
    }
}

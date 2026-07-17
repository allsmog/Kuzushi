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
}

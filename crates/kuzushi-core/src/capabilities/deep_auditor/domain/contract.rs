use crate::findings::TriageOutcome;
use serde::{Deserialize, Serialize};

pub const DEFAULT_MAX_STEPS: u32 = 24;

pub const DEFAULT_DEPOSIT_USD: f64 = 1.0;

/// Sampling temperature for every deep-audit model round-trip. Held at
/// 0.0 by default so re-running the auditor on the same finding emits
/// the same verdict — variance between runs was the loudest complaint
/// about the audit loop.
pub const DEFAULT_TEMPERATURE: f32 = 0.0;

/// How many independent audit passes to run for consensus voting. A
/// single pass is the cheap default; raise this to 3 (or 5) for
/// high-stakes findings and `run_deep_auditor` returns the majority
/// verdict — see capabilities/deep_auditor/application/consensus.rs.
pub const DEFAULT_PASSES: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnAnalysis {
    pub triggerable: bool,
    /// Human-readable rationale, present whether triggerable or not.
    pub rationale: String,
    /// 0.0..=1.0 confidence the verdict is correct.
    #[serde(default)]
    pub confidence: f32,
    /// Evidence citations the model relied on.
    #[serde(default)]
    pub evidence: Vec<EvidenceCitation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCitation {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    /// Free-form note, e.g. "user input enters here", "missing bounds check".
    #[serde(default)]
    pub note: String,
    /// Optional kind tag: "source" | "sink" | "guard" | "context".
    #[serde(default)]
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepAuditOutcome {
    pub triage: TriageOutcome,
    pub evidence: Vec<EvidenceCitation>,
    pub cost_usd: f64,
    /// False when at least one provider call did not report an exact cost.
    #[serde(default)]
    pub cost_usd_exact: bool,
    pub steps_used: u32,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct DeepAuditConfig {
    pub workspace_root: std::path::PathBuf,
    pub max_steps: u32,
    pub deposit_usd: f64,
    pub system_prompt: Option<String>,
    /// Include whitebox-static narrative, registry, and evidence-graph context in the prompt.
    pub include_static_evidence: bool,
    /// Sampling temperature for every model round-trip. 0.0 by default
    /// for verdict consistency; raise to 0.3-0.7 if you want a more
    /// exploratory pass.
    pub temperature: f32,
    /// Independent audit passes to run; majority verdict is reported
    /// when this is > 1. See domain::consensus for semantics. Default 1.
    pub passes: u32,
}

impl DeepAuditConfig {
    pub fn new(workspace_root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            max_steps: DEFAULT_MAX_STEPS,
            deposit_usd: DEFAULT_DEPOSIT_USD,
            system_prompt: None,
            include_static_evidence: true,
            temperature: DEFAULT_TEMPERATURE,
            passes: DEFAULT_PASSES,
        }
    }
}

const DEEP_AUDITOR_HEADER: &str = "You are Kuzushi's deep auditor. Verify whether the candidate finding is a genuine, triggerable \
vulnerability with realistic attacker input. Use code-navigation tools (read_source / \
read_definition / find_references / list_definitions) to inspect the code. Do not speculate \
beyond what you read.";

const DEEP_AUDITOR_METHOD: &str = "Method, with a target budget of 3-8 tool calls:
1. Read the function or block containing the alleged sink.
2. Read the immediate caller(s), dispatcher, route, handler, or job entry point that controls \
   reachability.
3. Trace attacker-controlled values from entry point to sink, naming source, transformations, \
   guards, and sink.
4. Before voting triggerable=true on a missing-local-check claim, check whether a centralized \
   validator, router, parser, schema, middleware, or privilege gate enforces the missing invariant \
   upstream.
5. Stop as soon as the verdict is supported by cited evidence. Reading more than 10 regions is \
   usually wasted budget; emit the current best verdict and mark uncertainty when needed.";

const DEEP_AUDITOR_OUTPUT: &str = "Return ONLY a JSON object matching this schema as your final message (no tool call, just JSON):
{
  \"triggerable\": bool,
  \"rationale\": \"one or two sentences naming the guard or missing guard and citing file:line\",
  \"confidence\": 0.0..=1.0,
  \"evidence\": [
    {\"file\": \"path/relative/to/root\", \"start_line\": int, \"end_line\": int,
     \"note\": \"short evidence note\", \"kind\": \"source|sink|guard|context\"}
  ]
}";

#[cfg(test)]
mod system_prompt_tests {
    use super::deep_auditor_system_prompt;
    use crate::prompts::PromptLanguage;

    #[test]
    fn validator_catalog_varies_by_detected_language() {
        let c = deep_auditor_system_prompt(PromptLanguage::CorCpp);
        let py = deep_auditor_system_prompt(PromptLanguage::Python);
        assert!(c.contains("netlink, ioctl"));
        assert!(!c.contains("Django/Flask/FastAPI"));
        assert!(py.contains("Django/Flask/FastAPI"));
        // Spine blocks are present regardless of language.
        assert!(c.contains("false-DISMISSAL traps"));
        assert!(py.contains("Assign confidence by evidence"));
    }
}

/// Assemble the deep-auditor system prompt, injecting the validator catalog for
/// the detected language/ecosystem.
pub(crate) fn deep_auditor_system_prompt(language: crate::prompts::PromptLanguage) -> String {
    let catalog = format!(
        "Language/ecosystem validator catalog:\n{}",
        crate::prompts::centralized_validator_catalog(language)
    );
    crate::prompts::assemble_system_prompt(
        DEEP_AUDITOR_HEADER,
        &[
            DEEP_AUDITOR_METHOD,
            crate::prompts::FALSE_POSITIVE_TAXONOMY,
            crate::prompts::CONFIDENCE_CALIBRATION,
            &catalog,
            DEEP_AUDITOR_OUTPUT,
        ],
    )
}

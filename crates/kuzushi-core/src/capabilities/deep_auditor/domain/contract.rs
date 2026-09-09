use super::TaintToolPolicy;
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
    /// None means reachability or impact remains unresolved, not refuted.
    /// Existing JSON boolean assessments remain readable as Some(bool).
    pub triggerable: Option<bool>,
    /// Human-readable rationale, present whether triggerable or not.
    pub rationale: String,
    /// 0.0..=1.0 confidence the verdict is correct.
    #[serde(default)]
    pub confidence: f32,
    /// Evidence citations the model relied on.
    #[serde(default)]
    pub evidence: Vec<EvidenceCitation>,
    /// `file:line` of the first caller/call-site actually read while tracing
    /// reachability (method step 2). Absent when no caller was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_link: Option<String>,
    /// Closed refutation vocabulary on `triggerable=false` verdicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refute_reason: Option<crate::findings::RefuteReason>,
}

/// Where an evidence citation actually came from. This is tracked at the point
/// of creation — it is NOT inferred from `kind`, because the prompt asks the
/// MODEL to emit `kind="guard"` citations, so a guard tag alone does not mean
/// the row was mined from the dataflow engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOrigin {
    /// Read or cited from source by the model (default for model-emitted
    /// citations and hand-read regions).
    #[default]
    CodeRead,
    /// Mined from the in-process cpg-rs dataflow engine (a witnessed flow).
    CpgPath,
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
    /// Real provenance of the citation. `skip_deserializing` so a model cannot
    /// forge cpg-rs provenance through its structured output — only kuzushi's
    /// own mining code sets `CpgPath`. Persisted (serialized) so the finding
    /// detail projection can label origin from tracked truth, not `kind`.
    #[serde(default, skip_deserializing)]
    pub origin: EvidenceOrigin,
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
    /// True when this outcome came from a consensus vote that split into a tie.
    /// A tie is the one verdict a different, operator-named tie-break model may
    /// legitimately revisit; single-pass outcomes are never splits.
    #[serde(default)]
    pub consensus_split: bool,
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
    /// Dataflow-tool policy offered to the auditor (off / available / build).
    pub taint_tools: TaintToolPolicy,
    /// Human-reviewed historical signal supplied by bulk triage. It is shown
    /// as advisory context and never changes the finding or tool policy.
    pub reviewed_refutation_context: Option<String>,
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
            taint_tools: TaintToolPolicy::default(),
            reviewed_refutation_context: None,
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
   reachability. Record the file:line of the first call site you actually read as first_link — \
   a plausible-sounding chain is not enough; the first link must be a location you inspected.
3. Trace attacker-controlled values from entry point to sink, naming source, transformations, \
   guards, and sink.
4. Before voting triggerable=true on a missing-local-check claim, check whether a centralized \
   validator, router, parser, schema, middleware, or privilege gate enforces the missing invariant \
   upstream.
5. Stop as soon as the verdict is supported by cited evidence. Reading more than 10 regions is \
   usually wasted budget; emit the current best verdict and mark uncertainty when needed.
6. Return triggerable=null when reachability or impact remains unresolved. An empty reference \
   search, an external/library caller, or a missing entry point is not evidence of safety. \
   A triggerable=false verdict requires cited evidence that defeats the claimed vulnerability. \
   For implausible_trigger, cite the inspected call path in first_link; without it, use null.";

const DEEP_AUDITOR_OUTPUT: &str = "Return ONLY a JSON object matching this schema as your final message (no tool call, just JSON):
{
  \"triggerable\": true|false|null (null means needs_review),
  \"rationale\": \"one or two sentences naming the guard or missing guard and citing file:line\",
  \"confidence\": 0.0..=1.0,
  \"first_link\": \"file:line of the first call site you actually read, or null\",
  \"refute_reason\": \"only when triggerable=false: doesnt_exist|already_handled|implausible_trigger|intentional_behavior|misread_code|duplicate|not_actionable, else null\",
  \"evidence\": [
    {\"file\": \"path/relative/to/root\", \"start_line\": int, \"end_line\": int,
     \"note\": \"short evidence note\", \"kind\": \"source|sink|guard|context\"}
  ]
}";

/// Extra method step advertised only when the auditor is offered the
/// `cpg_taint_paths` dataflow tool. A returned guard/authz annotation is
/// falsification evidence; an empty flow count is never proof of safety.
const DEEP_AUDITOR_TAINT_STEP: &str =
    "2b. When the alleged flow crosses functions, call cpg_taint_paths with regex \
source/sink patterns before reading callers by hand. A returned `guard` or `authz` annotation is \
falsification evidence: cite it as kind=\"guard\" and prefer triggerable=false. An empty flowCount \
is NOT evidence of safety — fall back to read_definition/find_references.";

#[cfg(test)]
mod system_prompt_tests {
    use super::deep_auditor_system_prompt;
    use crate::prompts::PromptLanguage;

    #[test]
    fn validator_catalog_varies_by_detected_language() {
        let c = deep_auditor_system_prompt(PromptLanguage::CorCpp, false);
        let py = deep_auditor_system_prompt(PromptLanguage::Python, false);
        assert!(c.contains("netlink, ioctl"));
        assert!(!c.contains("Django/Flask/FastAPI"));
        assert!(py.contains("Django/Flask/FastAPI"));
        // Spine blocks are present regardless of language.
        assert!(c.contains("false-DISMISSAL traps"));
        assert!(py.contains("Assign confidence by evidence"));
    }

    #[test]
    fn taint_step_appears_only_when_tools_available() {
        let without = deep_auditor_system_prompt(PromptLanguage::CorCpp, false);
        let with = deep_auditor_system_prompt(PromptLanguage::CorCpp, true);
        assert!(!without.contains("cpg_taint_paths"));
        assert!(with.contains("cpg_taint_paths"));
    }

    #[test]
    fn deep_auditor_prompt_never_carries_hunt_hints() {
        for language in [
            PromptLanguage::CorCpp,
            PromptLanguage::Rust,
            PromptLanguage::Go,
            PromptLanguage::TypeScript,
            PromptLanguage::Python,
            PromptLanguage::JavaSpring,
            PromptLanguage::Other,
        ] {
            for taint_tools in [false, true] {
                assert!(!deep_auditor_system_prompt(language, taint_tools)
                    .contains("investigation starting points"));
            }
        }
    }
}

/// Assemble the deep-auditor system prompt, injecting the validator catalog for
/// the detected language/ecosystem and the taint-tool method step when the
/// auditor is offered `cpg_taint_paths`.
pub(crate) fn deep_auditor_system_prompt(
    language: crate::prompts::PromptLanguage,
    taint_tools_available: bool,
) -> String {
    let catalog = format!(
        "Language/ecosystem validator catalog:\n{}",
        crate::prompts::centralized_validator_catalog(language)
    );
    crate::prompts::assemble_system_prompt(
        DEEP_AUDITOR_HEADER,
        &deep_auditor_blocks(&catalog, taint_tools_available),
    )
}

fn deep_auditor_blocks<'a>(catalog: &'a str, taint_tools_available: bool) -> Vec<&'a str> {
    let mut blocks = vec![DEEP_AUDITOR_METHOD];
    if taint_tools_available {
        blocks.push(DEEP_AUDITOR_TAINT_STEP);
    }
    blocks.extend_from_slice(&[
        crate::prompts::FALSE_POSITIVE_TAXONOMY,
        crate::prompts::CONFIDENCE_CALIBRATION,
        catalog,
        DEEP_AUDITOR_OUTPUT,
    ]);
    blocks
}

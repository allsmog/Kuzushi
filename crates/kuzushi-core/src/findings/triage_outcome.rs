use super::TriageVerdict;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TriageOutcome {
    pub verdict: TriageVerdict,
    pub confidence: f32,
    pub rationale: String,
    /// USD cost of the LLM call that produced this verdict. Populated
    /// by providers that surface usage (e.g. `AnthropicOAuthRuntime`
    /// reads `usage.input_tokens` / `usage.output_tokens` and applies
    /// the per-model rate). Defaults to `0.0`. Drives `triage:run`'s
    /// in-process cost cap.
    #[serde(default)]
    pub cost_usd: f64,
}

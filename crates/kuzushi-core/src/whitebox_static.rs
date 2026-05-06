use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::findings::{Finding, StaticProofState, TriageOutcome, TriageVerdict};
use crate::runtime::AgentToolPolicy;
use crate::source_span::extract_source_span;

pub const WHITEBOX_STATIC_AGENT_TOOL_PROFILE: &str = "whitebox-static";
pub const WHITEBOX_STATIC_READ_ONLY_AGENT_TOOLS: &[&str] = &["Read", "Glob", "Grep", "LS"];
pub const WHITEBOX_STATIC_TRIAGE_SYSTEM_PROMPT: &str = r#"You are Kuzushi's whitebox-static triage agent.
Use static source evidence only. Do not perform active exploitation, HTTP replay, fuzzing, live target scanning, PoC generation, or PoC execution.
Return only JSON matching the whitebox-static triage schema provided in the prompt.
Forbidden in whitebox-static triage: payloads, PoCs, exploit execution, runtime exploitability claims, and claims that something is runtime exploitable.
Use true_positive only when staticProofState is statically_confirmed and every material claim is backed by source citations. Otherwise use false_positive, by_design, or needs_review.
"#;
const WHITEBOX_STATIC_FORBIDDEN_AGENT_TOOLS: &[&str] = &[
    "bash",
    "shell",
    "sh",
    "zsh",
    "fish",
    "powershell",
    "cmd",
    "write",
    "edit",
    "multiedit",
    "patch",
    "applypatch",
    "apply_patch",
    "notebookedit",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisMode {
    Standard,
    WhiteboxStatic,
}

impl AnalysisMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::WhiteboxStatic => "whitebox-static",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxStaticPolicy {
    pub enabled: bool,
    pub mode: String,
    pub verify: bool,
    pub poc_harness: bool,
    pub poc_execution: bool,
    pub dynamic_analysis: bool,
    pub crypto_behavioral_testing: bool,
    pub patching: bool,
    pub auto_patch: bool,
    pub execution_proof_states: bool,
    pub runtime_exploitability_claims: bool,
    pub disabled: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxStaticTriageEndpoint {
    pub file_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxStaticTriagePathStep {
    pub file_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxStaticTriageCitation {
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxStaticTriageResponse {
    pub verdict: TriageVerdict,
    pub confidence: f32,
    pub static_proof_state: StaticProofState,
    pub source: WhiteboxStaticTriageEndpoint,
    pub sink: WhiteboxStaticTriageEndpoint,
    #[serde(default)]
    pub path: Vec<WhiteboxStaticTriagePathStep>,
    pub sanitizer_assessment: String,
    pub guard_assessment: String,
    #[serde(default)]
    pub citations: Vec<WhiteboxStaticTriageCitation>,
    #[serde(default)]
    pub assumptions: Vec<String>,
    #[serde(default)]
    pub missing_evidence: Vec<String>,
    pub trigger_narrative: String,
    pub impact_narrative: String,
    pub recommended_fix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedWhiteboxStaticCitation {
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxStaticCitationValidationReport {
    pub complete: bool,
    pub reasons: Vec<String>,
    pub verified_citations: Vec<VerifiedWhiteboxStaticCitation>,
}

impl WhiteboxStaticPolicy {
    fn active(disabled: Vec<String>) -> Self {
        Self {
            enabled: true,
            mode: AnalysisMode::WhiteboxStatic.as_str().to_string(),
            verify: false,
            poc_harness: false,
            poc_execution: false,
            dynamic_analysis: false,
            crypto_behavioral_testing: false,
            patching: false,
            auto_patch: false,
            execution_proof_states: false,
            runtime_exploitability_claims: false,
            disabled,
        }
    }

    pub fn to_json(&self) -> Value {
        json!(self)
    }
}

pub fn analysis_mode_from_input(input: &Value) -> Result<AnalysisMode> {
    if truthy_bool(input, &["whiteboxStatic", "whitebox_static"])? {
        return Ok(AnalysisMode::WhiteboxStatic);
    }

    let raw = input
        .get("mode")
        .or_else(|| input.get("preset"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("standard");
    match raw {
        "standard" | "default" | "sast" => Ok(AnalysisMode::Standard),
        "whitebox-static" => Ok(AnalysisMode::WhiteboxStatic),
        other => anyhow::bail!(
            "analysis mode {other:?} is unsupported; valid modes: standard, whitebox-static"
        ),
    }
}

pub fn whitebox_static_enabled(input: &Value) -> Result<bool> {
    Ok(analysis_mode_from_input(input)? == AnalysisMode::WhiteboxStatic)
}

pub fn default_whitebox_static_agent_tool_policy() -> AgentToolPolicy {
    AgentToolPolicy::new(
        WHITEBOX_STATIC_AGENT_TOOL_PROFILE,
        WHITEBOX_STATIC_READ_ONLY_AGENT_TOOLS.iter().copied(),
    )
}

pub fn agent_tool_policy_for_input(input: &Value) -> Result<AgentToolPolicy> {
    if whitebox_static_profile_requested(input)? {
        let policy = default_whitebox_static_agent_tool_policy();
        validate_whitebox_static_agent_tool_policy(&policy)?;
        Ok(policy)
    } else {
        Ok(AgentToolPolicy::default())
    }
}

pub fn whitebox_static_profile_requested(input: &Value) -> Result<bool> {
    for key in ["whiteboxStatic", "whitebox_static"] {
        if let Some(value) = input.get(key) {
            if let Some(enabled) = value.get("enabled").and_then(Value::as_bool) {
                return Ok(enabled);
            }
            return value
                .as_bool()
                .with_context(|| format!("{key} must be a boolean or policy object"));
        }
    }

    let raw_mode = input
        .get("mode")
        .or_else(|| input.get("preset"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    Ok(raw_mode == AnalysisMode::WhiteboxStatic.as_str())
}

pub fn validate_whitebox_static_agent_tool_policy(policy: &AgentToolPolicy) -> Result<()> {
    if policy.profile != WHITEBOX_STATIC_AGENT_TOOL_PROFILE {
        anyhow::bail!(
            "whitebox-static agent tool policy must use profile {WHITEBOX_STATIC_AGENT_TOOL_PROFILE:?}"
        );
    }
    if policy.tools.is_empty() {
        anyhow::bail!("whitebox-static agent tool policy must include read-only repo tools");
    }

    for tool in &policy.tools {
        if is_forbidden_agent_tool(tool) {
            anyhow::bail!(
                "whitebox-static agent tool policy cannot include execution or write tool {tool:?}"
            );
        }
        if !WHITEBOX_STATIC_READ_ONLY_AGENT_TOOLS
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(tool))
        {
            anyhow::bail!(
                "whitebox-static agent tool policy can only include read-only repo tools; unsupported tool {tool:?}"
            );
        }
    }
    Ok(())
}

pub fn whitebox_static_proof_state_from_str(value: &str) -> Result<StaticProofState> {
    if is_execution_proof_state(value) {
        return Ok(StaticProofState::NeedsRuntimeEvidence);
    }
    StaticProofState::try_from(value)
}

pub fn whitebox_static_proof_state_from_input(input: &Value) -> Result<Option<StaticProofState>> {
    for key in [
        "staticProofState",
        "static_proof_state",
        "proofState",
        "proof_state",
    ] {
        let Some(value) = input.get(key) else {
            continue;
        };
        let Some(raw) = value.as_str() else {
            anyhow::bail!("whitebox-static {key} must be a string");
        };
        return Ok(Some(whitebox_static_proof_state_from_str(raw)?));
    }
    Ok(None)
}

pub fn mark_whitebox_static_findings(
    findings: &mut [Finding],
    default_state: StaticProofState,
) -> Result<()> {
    for finding in findings {
        let state = finding.static_proof_state.unwrap_or(default_state);
        finding.set_static_proof_state(state);
    }
    Ok(())
}

pub fn whitebox_static_triage_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "verdict",
            "confidence",
            "staticProofState",
            "source",
            "sink",
            "path",
            "sanitizerAssessment",
            "guardAssessment",
            "citations",
            "assumptions",
            "missingEvidence",
            "triggerNarrative",
            "impactNarrative",
            "recommendedFix"
        ],
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["true_positive", "false_positive", "needs_review", "by_design"]
            },
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "staticProofState": {
                "type": "string",
                "enum": [
                    "signal_only",
                    "code_cited",
                    "source_sink_linked",
                    "sanitizer_checked",
                    "statically_confirmed",
                    "statically_rejected",
                    "needs_runtime_evidence"
                ]
            },
            "source": {"$ref": "#/$defs/endpoint"},
            "sink": {"$ref": "#/$defs/endpoint"},
            "path": {
                "type": "array",
                "items": {"$ref": "#/$defs/pathStep"}
            },
            "sanitizerAssessment": {"type": "string"},
            "guardAssessment": {"type": "string"},
            "citations": {
                "type": "array",
                "items": {"$ref": "#/$defs/citation"}
            },
            "assumptions": {"type": "array", "items": {"type": "string"}},
            "missingEvidence": {"type": "array", "items": {"type": "string"}},
            "triggerNarrative": {"type": "string"},
            "impactNarrative": {"type": "string"},
            "recommendedFix": {"type": "string"}
        },
        "$defs": {
            "endpoint": {
                "type": "object",
                "additionalProperties": false,
                "required": ["filePath", "summary"],
                "properties": {
                    "filePath": {"type": "string"},
                    "startLine": {"type": "integer", "minimum": 1},
                    "endLine": {"type": "integer", "minimum": 1},
                    "summary": {"type": "string"}
                }
            },
            "pathStep": {
                "type": "object",
                "additionalProperties": false,
                "required": ["filePath", "summary"],
                "properties": {
                    "filePath": {"type": "string"},
                    "line": {"type": "integer", "minimum": 1},
                    "summary": {"type": "string"}
                }
            },
            "citation": {
                "type": "object",
                "additionalProperties": false,
                "required": ["filePath", "startLine", "endLine"],
                "properties": {
                    "filePath": {"type": "string"},
                    "startLine": {"type": "integer", "minimum": 1},
                    "endLine": {"type": "integer", "minimum": 1},
                    "snippet": {"type": "string"},
                    "snippetHash": {"type": "string"}
                }
            }
        }
    })
}

pub fn build_whitebox_static_triage_prompt(
    finding: &Finding,
    operator_prompt: Option<&str>,
) -> Result<String> {
    let schema = serde_json::to_string_pretty(&whitebox_static_triage_schema())
        .context("Could not serialize whitebox-static triage schema")?;
    let finding_json =
        serde_json::to_string_pretty(finding).context("Could not serialize finding")?;
    let operator_prompt = operator_prompt
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("No additional operator instructions.");

    Ok(format!(
        r#"Whitebox-static triage task.

Operator instructions:
{operator_prompt}

Static-only rules:
- Use source-grounded static evidence only.
- Do not provide payloads, PoCs, exploit execution steps, HTTP replay, fuzzing, or live target scanning instructions.
- Do not make runtime exploitability claims and do not say the finding is runtime exploitable.
- If source evidence is insufficient, set staticProofState to needs_runtime_evidence and explain missingEvidence.
- Use statically_confirmed only when source, sink, path or local/direct reason, sanitizer assessment, guard assessment, and citations are all present.

Return only JSON matching this schema:
{schema}

Finding JSON:
{finding_json}"#
    ))
}

pub fn parse_whitebox_static_triage_response(value: Value) -> Result<WhiteboxStaticTriageResponse> {
    let mut response: WhiteboxStaticTriageResponse = serde_json::from_value(value)
        .context("whitebox-static triage response did not match schema")?;
    response.confidence = response.confidence.clamp(0.0, 1.0);
    Ok(response)
}

pub fn whitebox_static_triage_outcome(response: &WhiteboxStaticTriageResponse) -> TriageOutcome {
    TriageOutcome {
        verdict: response.verdict,
        confidence: response.confidence,
        rationale: format!(
            "staticProofState={}; trigger={}; impact={}; sanitizer={}; guard={}; missingEvidence={}",
            response.static_proof_state.as_str(),
            response.trigger_narrative.trim(),
            response.impact_narrative.trim(),
            response.sanitizer_assessment.trim(),
            response.guard_assessment.trim(),
            if response.missing_evidence.is_empty() {
                "none".to_string()
            } else {
                response.missing_evidence.join("; ")
            }
        ),
    }
}

pub fn validate_whitebox_static_triage_citations(
    repo_root: impl AsRef<Path>,
    response: &WhiteboxStaticTriageResponse,
) -> Result<WhiteboxStaticCitationValidationReport> {
    let repo_root = repo_root.as_ref();
    let mut reasons = Vec::new();
    let mut verified_citations = Vec::new();

    if response.citations.is_empty() {
        reasons.push("whitebox-static triage response did not include citations".to_string());
    }

    for citation in &response.citations {
        match verify_whitebox_static_triage_citation(repo_root, citation) {
            Ok(verified) => verified_citations.push(verified),
            Err(error) => reasons.push(format!(
                "citation {}:{}-{} is invalid: {error}",
                citation.file_path, citation.start_line, citation.end_line
            )),
        }
    }

    Ok(WhiteboxStaticCitationValidationReport {
        complete: reasons.is_empty(),
        reasons,
        verified_citations,
    })
}

pub fn apply_whitebox_static_citation_validation(
    response: &mut WhiteboxStaticTriageResponse,
    report: &WhiteboxStaticCitationValidationReport,
) {
    if report.complete || response.static_proof_state != StaticProofState::StaticallyConfirmed {
        return;
    }

    response.static_proof_state = StaticProofState::NeedsRuntimeEvidence;
    if response.verdict == TriageVerdict::TruePositive {
        response.verdict = TriageVerdict::NeedsReview;
        response.confidence = response.confidence.min(0.5);
    }

    let reason = format!("Unverified source citations: {}", report.reasons.join("; "));
    if !response
        .missing_evidence
        .iter()
        .any(|existing| existing == &reason)
    {
        response.missing_evidence.push(reason);
    }
}

fn verify_whitebox_static_triage_citation(
    repo_root: &Path,
    citation: &WhiteboxStaticTriageCitation,
) -> Result<VerifiedWhiteboxStaticCitation> {
    let has_snippet = citation
        .snippet
        .as_deref()
        .is_some_and(|snippet| !snippet.trim().is_empty());
    let has_hash = citation
        .snippet_hash
        .as_deref()
        .is_some_and(|hash| !hash.trim().is_empty());
    if !has_snippet && !has_hash {
        bail!("citation must include snippet or snippetHash");
    }

    let span = extract_source_span(
        repo_root,
        citation.file_path.as_str(),
        citation.start_line,
        citation.end_line,
    )?;
    if let Some(snippet) = citation
        .snippet
        .as_deref()
        .map(|snippet| snippet.trim_end_matches(|ch| ch == '\r' || ch == '\n'))
        .filter(|snippet| !snippet.trim().is_empty())
    {
        if snippet != span.snippet {
            bail!("snippet does not match current source");
        }
    }
    if let Some(snippet_hash) = citation
        .snippet_hash
        .as_deref()
        .map(str::trim)
        .filter(|hash| !hash.is_empty())
    {
        if snippet_hash != span.content_hash {
            bail!("snippetHash does not match current source");
        }
    }

    Ok(VerifiedWhiteboxStaticCitation {
        file_path: span.file_path,
        start_line: span.start_line,
        end_line: span.end_line,
        content_hash: span.content_hash,
    })
}

fn is_forbidden_agent_tool(tool: &str) -> bool {
    let normalized = normalize_agent_tool_name(tool);
    WHITEBOX_STATIC_FORBIDDEN_AGENT_TOOLS
        .iter()
        .any(|forbidden| *forbidden == normalized)
}

fn normalize_agent_tool_name(tool: &str) -> String {
    tool.chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .flat_map(char::to_lowercase)
        .collect()
}

pub fn apply_whitebox_static_sast_policy(
    input: Value,
) -> Result<(Value, Option<WhiteboxStaticPolicy>)> {
    let mode = analysis_mode_from_input(&input)?;
    if mode != AnalysisMode::WhiteboxStatic {
        return Ok((input, None));
    }

    let mut object = input
        .as_object()
        .cloned()
        .context("sast:scan input must be a JSON object")?;
    let mut disabled = Vec::new();
    force_false(&mut object, &mut disabled, "verify");
    force_false(&mut object, &mut disabled, "autoPatch");
    force_false(&mut object, &mut disabled, "auto_patch");
    force_false(&mut object, &mut disabled, "patch");
    force_false(&mut object, &mut disabled, "patching");
    force_false(&mut object, &mut disabled, "poc");
    force_false(&mut object, &mut disabled, "pocHarness");
    force_false(&mut object, &mut disabled, "poc_harness");
    force_false(&mut object, &mut disabled, "pocExecution");
    force_false(&mut object, &mut disabled, "poc_execution");
    force_false(&mut object, &mut disabled, "dynamicAnalysis");
    force_false(&mut object, &mut disabled, "dynamic_analysis");
    force_false(&mut object, &mut disabled, "cryptoBehavioralTesting");
    force_false(&mut object, &mut disabled, "crypto_behavioral_testing");
    force_false(&mut object, &mut disabled, "runtimeExploitabilityClaims");
    force_false(&mut object, &mut disabled, "runtime_exploitability_claims");
    force_false(&mut object, &mut disabled, "executionProofStates");
    force_false(&mut object, &mut disabled, "execution_proof_states");

    rewrite_execution_proof_state(&mut object, &mut disabled, "proofState");
    rewrite_execution_proof_state(&mut object, &mut disabled, "proof_state");
    rewrite_execution_proof_states(&mut object, &mut disabled, "proofStates");
    rewrite_execution_proof_states(&mut object, &mut disabled, "proof_states");

    object.insert(
        "mode".to_string(),
        Value::String(AnalysisMode::WhiteboxStatic.as_str().to_string()),
    );
    object.insert(
        "whiteboxStatic".to_string(),
        WhiteboxStaticPolicy::active(disabled.clone()).to_json(),
    );

    Ok((
        Value::Object(object),
        Some(WhiteboxStaticPolicy::active(disabled)),
    ))
}

fn force_false(object: &mut Map<String, Value>, disabled: &mut Vec<String>, key: &str) {
    let was_enabled = object.get(key).and_then(Value::as_bool).unwrap_or(false);
    object.insert(key.to_string(), Value::Bool(false));
    if was_enabled {
        disabled.push(key.to_string());
    }
}

fn rewrite_execution_proof_state(
    object: &mut Map<String, Value>,
    disabled: &mut Vec<String>,
    key: &str,
) {
    if object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(is_execution_proof_state)
    {
        object.insert(
            key.to_string(),
            Value::String("needs_runtime_evidence".to_string()),
        );
        disabled.push(key.to_string());
    }
}

fn rewrite_execution_proof_states(
    object: &mut Map<String, Value>,
    disabled: &mut Vec<String>,
    key: &str,
) {
    let Some(values) = object.get(key).and_then(Value::as_array) else {
        return;
    };
    if !values
        .iter()
        .filter_map(Value::as_str)
        .any(is_execution_proof_state)
    {
        return;
    }
    object.insert(
        key.to_string(),
        Value::Array(vec![Value::String("needs_runtime_evidence".to_string())]),
    );
    disabled.push(key.to_string());
}

fn is_execution_proof_state(value: &str) -> bool {
    matches!(
        value.trim(),
        "execution_confirmed"
            | "runtime_confirmed"
            | "dynamic_confirmed"
            | "exploit_confirmed"
            | "poc_confirmed"
    )
}

fn truthy_bool(input: &Value, keys: &[&str]) -> Result<bool> {
    for key in keys {
        if let Some(value) = input.get(*key) {
            if let Some(enabled) = value.get("enabled").and_then(Value::as_bool) {
                return Ok(enabled);
            }
            return value
                .as_bool()
                .with_context(|| format!("{key} must be a boolean"));
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitebox_static_policy_disables_execution_features_and_proof_states() {
        let (sanitized, policy) = apply_whitebox_static_sast_policy(json!({
            "mode": "whitebox-static",
            "verify": true,
            "autoPatch": true,
            "pocHarness": true,
            "pocExecution": true,
            "dynamicAnalysis": true,
            "cryptoBehavioralTesting": true,
            "patching": true,
            "proofState": "execution_confirmed",
            "proofStates": ["signal_only", "runtime_confirmed"]
        }))
        .unwrap();
        let policy = policy.unwrap();

        assert!(policy.enabled);
        assert!(!policy.verify);
        assert!(!policy.poc_harness);
        assert!(!policy.poc_execution);
        assert!(!policy.dynamic_analysis);
        assert!(!policy.crypto_behavioral_testing);
        assert!(!policy.patching);
        assert!(!policy.auto_patch);
        assert!(!policy.execution_proof_states);
        assert!(!policy.runtime_exploitability_claims);
        assert_eq!(sanitized["verify"], json!(false));
        assert_eq!(sanitized["autoPatch"], json!(false));
        assert_eq!(sanitized["proofState"], json!("needs_runtime_evidence"));
        assert_eq!(sanitized["proofStates"], json!(["needs_runtime_evidence"]));
        assert!(!serde_json::to_string(&sanitized)
            .unwrap()
            .contains("execution_confirmed"));
    }

    #[test]
    fn standard_mode_preserves_input() {
        let input = json!({"mode": "standard", "verify": true});
        let (sanitized, policy) = apply_whitebox_static_sast_policy(input.clone()).unwrap();

        assert_eq!(sanitized, input);
        assert!(policy.is_none());
    }

    #[test]
    fn whitebox_agent_tools_are_read_only_repo_tools() {
        let policy = default_whitebox_static_agent_tool_policy();

        assert_eq!(policy.profile, "whitebox-static");
        assert_eq!(policy.tools, vec!["Read", "Glob", "Grep", "LS"]);
        validate_whitebox_static_agent_tool_policy(&policy).unwrap();
    }

    #[test]
    fn whitebox_agent_tools_reject_shell_write_and_patch_tools() {
        for forbidden in ["Bash", "shell", "Write", "Edit", "patch", "apply_patch"] {
            let policy = AgentToolPolicy::new("whitebox-static", ["Read", forbidden]);
            let err = validate_whitebox_static_agent_tool_policy(&policy)
                .unwrap_err()
                .to_string();

            assert!(err.contains("cannot include execution or write tool"));
        }
    }

    #[test]
    fn whitebox_agent_tools_reject_non_repo_read_only_tools() {
        let policy = AgentToolPolicy::new("whitebox-static", ["Read", "Fetch"]);
        let err = validate_whitebox_static_agent_tool_policy(&policy)
            .unwrap_err()
            .to_string();

        assert!(err.contains("can only include read-only repo tools"));
    }

    #[test]
    fn standard_mode_gets_default_empty_agent_tool_policy() {
        let policy = agent_tool_policy_for_input(&json!({"mode": "standard"})).unwrap();

        assert!(policy.is_default());
    }

    #[test]
    fn whitebox_mode_gets_read_only_agent_tool_policy() {
        let policy = agent_tool_policy_for_input(&json!({"mode": "whitebox-static"})).unwrap();

        assert_eq!(policy.profile, "whitebox-static");
        assert_eq!(policy.tools, vec!["Read", "Glob", "Grep", "LS"]);
    }

    #[test]
    fn static_proof_state_from_whitebox_input_downgrades_execution_confirmation() {
        let state = whitebox_static_proof_state_from_input(&json!({
            "staticProofState": "execution_confirmed"
        }))
        .unwrap();

        assert_eq!(state, Some(StaticProofState::NeedsRuntimeEvidence));
    }

    #[test]
    fn static_proof_marking_sets_default_without_execution_states() {
        let mut findings = vec![
            Finding::new_semgrep(
                "demo.signal",
                "src/app.ts",
                1,
                Some(1),
                crate::findings::Severity::High,
                "scanner signal",
            ),
            Finding::new_semgrep(
                "demo.linked",
                "src/db.ts",
                5,
                Some(5),
                crate::findings::Severity::High,
                "source reaches sink",
            )
            .with_static_proof_state(StaticProofState::SourceSinkLinked),
        ];

        mark_whitebox_static_findings(&mut findings, StaticProofState::SignalOnly).unwrap();

        assert_eq!(
            findings[0].static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
        assert_eq!(
            findings[1].static_proof_state,
            Some(StaticProofState::SourceSinkLinked)
        );
    }

    #[test]
    fn whitebox_triage_prompt_schema_includes_static_contract_and_forbidden_terms() {
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            7,
            Some(8),
            crate::findings::Severity::High,
            "request parameter reaches SQL query",
        );
        let schema = whitebox_static_triage_schema();
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();

        for field in [
            "verdict",
            "staticProofState",
            "source",
            "sink",
            "path",
            "sanitizerAssessment",
            "guardAssessment",
            "citations",
            "assumptions",
            "missingEvidence",
            "triggerNarrative",
            "impactNarrative",
            "recommendedFix",
        ] {
            assert!(required.contains(&field), "missing schema field {field}");
        }

        let prompt =
            build_whitebox_static_triage_prompt(&finding, Some("Use only citations.")).unwrap();
        assert!(prompt.contains("payloads"));
        assert!(prompt.contains("PoCs"));
        assert!(prompt.contains("exploit execution"));
        assert!(prompt.contains("runtime exploitability claims"));
        assert!(prompt.contains("staticProofState"));
        assert!(prompt.contains("request parameter reaches SQL query"));

        assert!(WHITEBOX_STATIC_TRIAGE_SYSTEM_PROMPT.contains("payloads"));
        assert!(WHITEBOX_STATIC_TRIAGE_SYSTEM_PROMPT.contains("PoCs"));
        assert!(WHITEBOX_STATIC_TRIAGE_SYSTEM_PROMPT.contains("exploit execution"));
        assert!(WHITEBOX_STATIC_TRIAGE_SYSTEM_PROMPT.contains("runtime exploitability claims"));
    }

    #[test]
    fn whitebox_triage_response_parses_and_maps_to_triage_outcome() {
        let response = parse_whitebox_static_triage_response(json!({
            "verdict": "true_positive",
            "confidence": 1.7,
            "staticProofState": "statically_confirmed",
            "source": {
                "filePath": "src/routes.ts",
                "startLine": 4,
                "summary": "request query parameter"
            },
            "sink": {
                "filePath": "src/db.ts",
                "startLine": 9,
                "summary": "raw SQL query"
            },
            "path": [{
                "filePath": "src/routes.ts",
                "line": 4,
                "summary": "q flows into search"
            }],
            "sanitizerAssessment": "No sanitizer is visible on the cited path.",
            "guardAssessment": "Authentication exists, but no SQL construction guard is visible.",
            "citations": [{
                "filePath": "src/routes.ts",
                "startLine": 4,
                "endLine": 4,
                "snippet": "const id = req.query.id;",
                "snippetHash": "sha256:demo"
            }],
            "assumptions": ["The route is reachable from Express."],
            "missingEvidence": ["Runtime reachability is not assessed."],
            "triggerNarrative": "A request query value reaches search construction statically.",
            "impactNarrative": "The static sink is a database query boundary.",
            "recommendedFix": "Use parameterized queries."
        }))
        .unwrap();

        assert_eq!(response.confidence, 1.0);
        assert_eq!(
            response.static_proof_state,
            StaticProofState::StaticallyConfirmed
        );

        let outcome = whitebox_static_triage_outcome(&response);
        assert_eq!(outcome.verdict, TriageVerdict::TruePositive);
        assert_eq!(outcome.confidence, 1.0);
        assert!(outcome
            .rationale
            .contains("staticProofState=statically_confirmed"));
        assert!(!outcome.rationale.contains("Use parameterized queries"));
    }

    #[test]
    fn whitebox_citations_verify_current_source_snippet_and_hash() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("src/db.ts"),
            "const q = req.query.q;\ndb.query(q);\n",
        )
        .unwrap();
        let snippet = "db.query(q);";
        let response = whitebox_response_with_citations(vec![WhiteboxStaticTriageCitation {
            file_path: "src/db.ts".to_string(),
            start_line: 2,
            end_line: 2,
            snippet: Some(snippet.to_string()),
            snippet_hash: Some(crate::static_evidence::static_content_hash(snippet)),
        }]);

        let report = validate_whitebox_static_triage_citations(temp.path(), &response).unwrap();

        assert!(report.complete, "{:?}", report.reasons);
        assert_eq!(report.verified_citations.len(), 1);
        assert_eq!(report.verified_citations[0].file_path, "src/db.ts");
    }

    #[test]
    fn whitebox_citations_reject_out_of_repo_and_bad_lines() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/db.ts"), "db.query(q);\n").unwrap();

        let out_of_repo = whitebox_response_with_citations(vec![WhiteboxStaticTriageCitation {
            file_path: "../outside.ts".to_string(),
            start_line: 1,
            end_line: 1,
            snippet: Some("db.query(q);".to_string()),
            snippet_hash: None,
        }]);
        let bad_line = whitebox_response_with_citations(vec![WhiteboxStaticTriageCitation {
            file_path: "src/db.ts".to_string(),
            start_line: 9,
            end_line: 9,
            snippet: Some("db.query(q);".to_string()),
            snippet_hash: None,
        }]);

        let out_report =
            validate_whitebox_static_triage_citations(temp.path(), &out_of_repo).unwrap();
        let line_report =
            validate_whitebox_static_triage_citations(temp.path(), &bad_line).unwrap();

        assert!(!out_report.complete);
        assert!(out_report
            .reasons
            .iter()
            .any(|reason| reason.contains("parent traversal")));
        assert!(!line_report.complete);
        assert!(line_report
            .reasons
            .iter()
            .any(|reason| reason.contains("exceeds file line count")));
    }

    #[test]
    fn whitebox_citations_reject_stale_snippet_or_hash() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/db.ts"), "db.query(q);\n").unwrap();

        let stale_snippet = whitebox_response_with_citations(vec![WhiteboxStaticTriageCitation {
            file_path: "src/db.ts".to_string(),
            start_line: 1,
            end_line: 1,
            snippet: Some("db.query(req.body.q);".to_string()),
            snippet_hash: None,
        }]);
        let stale_hash = whitebox_response_with_citations(vec![WhiteboxStaticTriageCitation {
            file_path: "src/db.ts".to_string(),
            start_line: 1,
            end_line: 1,
            snippet: None,
            snippet_hash: Some("sha256:stale".to_string()),
        }]);

        let snippet_report =
            validate_whitebox_static_triage_citations(temp.path(), &stale_snippet).unwrap();
        let hash_report =
            validate_whitebox_static_triage_citations(temp.path(), &stale_hash).unwrap();

        assert!(!snippet_report.complete);
        assert!(snippet_report
            .reasons
            .iter()
            .any(|reason| reason.contains("snippet does not match")));
        assert!(!hash_report.complete);
        assert!(hash_report
            .reasons
            .iter()
            .any(|reason| reason.contains("snippetHash does not match")));
    }

    #[test]
    fn whitebox_citations_downgrade_statically_confirmed_when_unverified() {
        let mut response = whitebox_response_with_citations(vec![WhiteboxStaticTriageCitation {
            file_path: "src/db.ts".to_string(),
            start_line: 1,
            end_line: 1,
            snippet: Some("stale".to_string()),
            snippet_hash: None,
        }]);
        let report = WhiteboxStaticCitationValidationReport {
            complete: false,
            reasons: vec![
                "citation src/db.ts:1-1 is invalid: snippet does not match current source"
                    .to_string(),
            ],
            verified_citations: Vec::new(),
        };

        apply_whitebox_static_citation_validation(&mut response, &report);

        assert_eq!(response.verdict, TriageVerdict::NeedsReview);
        assert_eq!(
            response.static_proof_state,
            StaticProofState::NeedsRuntimeEvidence
        );
        assert_eq!(response.confidence, 0.5);
        assert!(response
            .missing_evidence
            .iter()
            .any(|item| item.contains("Unverified source citations")));
    }

    fn whitebox_response_with_citations(
        citations: Vec<WhiteboxStaticTriageCitation>,
    ) -> WhiteboxStaticTriageResponse {
        WhiteboxStaticTriageResponse {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.9,
            static_proof_state: StaticProofState::StaticallyConfirmed,
            source: WhiteboxStaticTriageEndpoint {
                file_path: "src/db.ts".to_string(),
                start_line: Some(1),
                end_line: Some(1),
                summary: "request source".to_string(),
            },
            sink: WhiteboxStaticTriageEndpoint {
                file_path: "src/db.ts".to_string(),
                start_line: Some(1),
                end_line: Some(1),
                summary: "database query sink".to_string(),
            },
            path: Vec::new(),
            sanitizer_assessment: "No sanitizer is visible.".to_string(),
            guard_assessment: "No guard is visible.".to_string(),
            citations,
            assumptions: vec!["Static source is current.".to_string()],
            missing_evidence: vec!["Runtime behavior is not assessed.".to_string()],
            trigger_narrative: "A request value reaches a static sink.".to_string(),
            impact_narrative: "The sink is security-sensitive.".to_string(),
            recommended_fix: "Use a safe API.".to_string(),
        }
    }
}

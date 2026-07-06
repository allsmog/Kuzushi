use super::*;

pub const WHITEBOX_STATIC_AGENT_TOOL_PROFILE: &str = "whitebox-static";

pub const WHITEBOX_STATIC_READ_ONLY_AGENT_TOOLS: &[&str] = &["Read", "Glob", "Grep", "LS"];

const WHITEBOX_STATIC_HEADER: &str = "You are Kuzushi's agentic SAST scanner operating in whitebox-static mode. \
You perform source-only analysis. You may reason about possible trigger paths, but you must \
not claim runtime exploitation, execute payloads, generate PoCs, replay HTTP requests, fuzz, \
scan live targets, patch files, or use shell/network/write tools.";

const WHITEBOX_STATIC_PROOF_STATE_RULES: &str = "Static proof-state rules:
- signal_only: pattern or heuristic only; no precise code citation.
- code_cited: vulnerable-looking code cited, but source/sink/guard not fully linked.
- source_sink_linked: source and sink are linked with static reasoning.
- statically_confirmed: source, sink, path, and absent/bypassed guard are cited and no runtime \
  evidence is required to establish the static vulnerability condition.
- statically_rejected: cited guard, validator, constant sink, privilege gate, or unreachable path \
  defeats the claim.
- needs_runtime_evidence: static evidence is insufficient to decide triggerability.

Every claim must cite repository source lines and explain source, sink, path, sanitizer \
assessment, guard assessment, assumptions, and missing evidence. Use trigger and impact \
narratives only for static trigger path and potential impact. If citations are missing or \
stale, prefer needs_runtime_evidence or needs_review instead of statically_confirmed. Never \
mark a finding execution-confirmed.";

const WHITEBOX_STATIC_SCHEMA: &str = r#"Return only JSON matching:
{"findings":[{"ruleId":"short-rule-id","title":"short title","verdict":"true_positive|false_positive|needs_review","staticProofState":"signal_only|code_cited|source_sink_linked|sanitizer_checked|statically_confirmed|statically_rejected|needs_runtime_evidence","severity":"critical|high|medium|low|info","confidence":"high|medium|low","source":{"kind":"entrypoint|attacker_input|unknown","filePath":"relative/path","startLine":1,"endLine":1,"description":"source evidence"},"sink":{"kind":"sql_query|command_execution|deserialization|file_write|authz_boundary|other","filePath":"relative/path","startLine":1,"endLine":1,"description":"sink evidence"},"path":{"kind":"direct|dataflow|local|unknown","explanation":"static source-to-sink reasoning","steps":[{"filePath":"relative/path","startLine":1,"endLine":1,"description":"flow step"}]},"sanitizerAssessment":{"status":"present|absent|unknown","explanation":"static assessment"},"guardAssessment":{"status":"present|absent|unknown","explanation":"static assessment"},"citations":[{"filePath":"relative/path","startLine":1,"endLine":1,"snippet":"exact source snippet"}],"assumptions":["static assumption"],"missingEvidence":["runtime evidence not assessed"],"triggerNarrative":"static trigger path only","impactNarrative":"potential impact and static evidence limits","recommendedFix":"source-level remediation"}]}.
Do not include payloads, PoCs, exploit execution instructions, HTTP replay, fuzzing, live target scanning, or runtime exploitability claims. Never mark a finding execution-confirmed."#;

/// Assemble the whitebox-static system prompt from the shared spine. The static
/// finding schema is retained inline because the whitebox agentic-sast path
/// enforces only a generic `{findings:[...]}` contract, so the rich static
/// fields must be described in the prompt.
pub fn whitebox_static_triage_system_prompt_text() -> String {
    crate::prompts::assemble_system_prompt(
        WHITEBOX_STATIC_HEADER,
        &[
            crate::prompts::ATTACKER_METHODOLOGY,
            crate::prompts::FALSE_POSITIVE_TAXONOMY,
            crate::prompts::CONFIDENCE_CALIBRATION,
            crate::prompts::EMPTY_FINDINGS_OK,
            WHITEBOX_STATIC_PROOF_STATE_RULES,
            WHITEBOX_STATIC_SCHEMA,
        ],
    )
}

pub const WHITEBOX_STATIC_TRIAGE_PROMPT_BLOCK: &str = r#"Whitebox-static triage constraints:
- Static-only analysis: no active exploitation, no HTTP replay, no fuzzing, no live target scanning, no PoC generation, and no PoC execution.
- Every reported claim must cite repository source lines and explain the static source, sink, path, sanitizer assessment, guard assessment, assumptions, and missing evidence.
- Use triggerNarrative and impactNarrative only for static trigger path and potential impact; runtime exploitability is not assessed in whitebox-static mode.
- If citations are missing or stale, prefer needs_runtime_evidence or needs_review instead of statically_confirmed."#;

pub(crate) const WHITEBOX_STATIC_FORBIDDEN_AGENT_TOOLS: &[&str] = &[
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

impl WhiteboxStaticPolicy {
    pub(crate) fn active(disabled: Vec<String>) -> Self {
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

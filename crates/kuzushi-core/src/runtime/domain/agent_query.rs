use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageRequest {
    pub model: String,
    pub cwd: PathBuf,
    pub finding: Finding,
    pub prompt_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentQueryRequest {
    pub model: String,
    pub cwd: PathBuf,
    pub system_prompt: String,
    pub prompt: String,
    #[serde(default)]
    pub tool_policy: AgentToolPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_output: Option<AgentStructuredOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_options: Option<AgentRuntimeOptions>,
    /// Sampling temperature (0.0..=1.0). When set, the bridge forwards
    /// it to the provider; when None the provider's default is used.
    /// Set this near 0 for audit / triage flows where determinism
    /// matters (deep-audit relies on it to reduce verdict variance).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

impl AgentQueryRequest {
    pub fn new(
        model: impl Into<String>,
        cwd: impl Into<PathBuf>,
        system_prompt: impl Into<String>,
        prompt: impl Into<String>,
    ) -> Self {
        Self {
            model: model.into(),
            cwd: cwd.into(),
            system_prompt: system_prompt.into(),
            prompt: prompt.into(),
            tool_policy: AgentToolPolicy::default(),
            structured_output: None,
            thinking_level: None,
            max_output_tokens: None,
            runtime_options: None,
            temperature: None,
        }
    }

    pub fn with_tool_policy(mut self, tool_policy: AgentToolPolicy) -> Self {
        self.tool_policy = tool_policy;
        self
    }

    pub fn with_structured_output(mut self, structured_output: AgentStructuredOutput) -> Self {
        self.structured_output = Some(structured_output);
        self
    }

    pub fn with_thinking_level(mut self, thinking_level: impl Into<String>) -> Self {
        self.thinking_level = Some(thinking_level.into());
        self
    }

    pub fn with_max_output_tokens(mut self, tokens: u32) -> Self {
        self.max_output_tokens = Some(tokens);
        self
    }

    pub fn with_runtime_options(mut self, runtime_options: AgentRuntimeOptions) -> Self {
        self.runtime_options = Some(runtime_options);
        self
    }

    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentRuntimeOptions {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mcp_environment: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_verbose: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_log_path: Option<String>,
}

impl AgentRuntimeOptions {
    pub fn is_empty(&self) -> bool {
        self.mcp_environment.is_empty()
            && self.mcp_tool_timeout_ms.is_none()
            && self.bridge_verbose.is_none()
            && self.bridge_log_path.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentStructuredOutput {
    pub name: String,
    pub schema: Value,
    #[serde(default)]
    pub strict: bool,
}

impl AgentStructuredOutput {
    pub fn json_schema(name: impl Into<String>, schema: Value) -> Self {
        Self {
            name: name.into(),
            schema,
            strict: true,
        }
    }
}

pub fn append_structured_output_contract(
    system_prompt: &str,
    structured_output: Option<&AgentStructuredOutput>,
) -> String {
    let Some(contract) = structured_output else {
        return system_prompt.to_string();
    };
    let schema = serde_json::to_string_pretty(&contract.schema)
        .unwrap_or_else(|_| contract.schema.to_string());
    let strict = if contract.strict { "strict " } else { "" };
    format!(
        "{system_prompt}\n\nStructured output contract:\n\
         Return only {strict}JSON for `{name}`. Do not include markdown fences, prose, or trailing commentary.\n\
         Required JSON schema:\n{schema}",
        name = contract.name,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentToolPolicy {
    pub profile: String,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub mcps: bool,
}

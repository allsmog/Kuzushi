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
    /// If true, the bridge attaches the kuzushi MCP servers
    /// (tree-sitter, joern, codeql) as agent tools alongside whatever
    /// the `profile`/`tools` fields specify. This lets a module like
    /// taint-iris-next opt every hunt into the MCP triangulation
    /// surface without forcing the operator to set
    /// `KUZUSHI_AGENT_MCPS=1` in their shell. The env var still works
    /// as an override for ad-hoc operator runs.
    #[serde(default)]
    pub mcps: bool,
}

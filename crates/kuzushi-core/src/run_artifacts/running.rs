use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunLlmCallAudit {
    pub n: usize,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verb: Option<String>,
    pub model: String,
    pub provider: String,
    pub prompt_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunHouseRuleFingerprint {
    pub module: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunPromptOverrideFingerprint {
    pub module: String,
    pub verb: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunEnvFingerprint {
    pub key: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunTargetGitMetadata {
    pub sha: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub dirty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunSummary {
    pub run_id: String,
    pub kind: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub target: String,
    pub started_at_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kuzushi_version: Option<String>,
    /// Version of the shared agentic prompt spine that produced this run's
    /// prompts. Bumped whenever spine blocks, the untrusted-data boundary,
    /// the false-positive taxonomy, or validator catalogs change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_spine_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub house_rules: Vec<RunHouseRuleFingerprint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_overrides: Vec<RunPromptOverrideFingerprint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_model_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_fingerprint: Vec<RunEnvFingerprint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_git: Option<RunTargetGitMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub llm_calls: Vec<RunLlmCallAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_malformed_lines: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cli_args: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub loaded_modules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<RunArtifact>,
}

impl RunSummary {
    pub fn running(
        run_id: impl Into<String>,
        kind: impl Into<String>,
        tool: Option<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            kind: kind.into(),
            status: "running".to_string(),
            tool,
            target: target.into(),
            started_at_unix: now_unix(),
            completed_at_unix: None,
            findings: None,
            cost_usd: None,
            error: None,
            process_id: None,
            kuzushi_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            prompt_spine_version: Some(crate::prompts::PROMPT_SPINE_VERSION.to_string()),
            git_sha: build_git_sha(),
            git_branch: build_git_branch(),
            model: None,
            config_hash: None,
            platform: Some(runtime_platform()),
            house_rules: Vec::new(),
            prompt_overrides: Vec::new(),
            threat_model_sha256: None,
            env_fingerprint: Vec::new(),
            target_git: None,
            llm_calls: Vec::new(),
            trace_malformed_lines: None,
            cli_args: Vec::new(),
            loaded_modules: Vec::new(),
            artifacts: Vec::new(),
        }
    }

    pub fn complete(mut self) -> Self {
        self.status = "completed".to_string();
        self.completed_at_unix = Some(now_unix());
        self.process_id = None;
        self
    }

    pub fn failed(mut self, error: impl Into<String>) -> Self {
        self.status = "failed".to_string();
        self.completed_at_unix = Some(now_unix());
        self.error = Some(error.into());
        self.process_id = None;
        self
    }

    pub fn interrupted(mut self, error: impl Into<String>) -> Self {
        self.status = "interrupted".to_string();
        self.completed_at_unix = Some(now_unix());
        self.error = Some(error.into());
        self.process_id = None;
        self
    }

    pub fn canceled(mut self, reason: impl Into<String>) -> Self {
        self.status = "canceled".to_string();
        self.completed_at_unix = Some(now_unix());
        self.error = Some(reason.into());
        self.process_id = None;
        self
    }

    pub fn skipped(mut self, reason: impl Into<String>) -> Self {
        self.status = "skipped".to_string();
        self.completed_at_unix = Some(now_unix());
        self.error = Some(reason.into());
        self.process_id = None;
        self
    }

    pub fn with_process_id(mut self, process_id: u32) -> Self {
        self.process_id = Some(process_id);
        self
    }

    pub fn with_findings(mut self, findings: Option<u64>) -> Self {
        self.findings = findings;
        self
    }

    pub fn with_cost(mut self, cost_usd: Option<f64>) -> Self {
        self.cost_usd = cost_usd;
        self
    }

    pub fn with_model(mut self, model: Option<String>) -> Self {
        self.model = non_empty_metadata(model);
        self
    }

    pub fn with_config_hash(mut self, config_hash: Option<String>) -> Self {
        self.config_hash = non_empty_metadata(config_hash);
        self
    }

    pub fn with_reproducibility_from(mut self, source: &Self) -> Self {
        self.kuzushi_version = source.kuzushi_version.clone();
        self.prompt_spine_version = source.prompt_spine_version.clone();
        self.git_sha = source.git_sha.clone();
        self.git_branch = source.git_branch.clone();
        // A resolved runtime may be the first producer able to report the
        // effective model. Preserve a model captured at start, but allow the
        // terminal result to fill an absent value without refreshing the rest
        // of the start-time reproducibility snapshot.
        self.model = source.model.clone().or(self.model);
        self.config_hash = source.config_hash.clone();
        self.platform = source.platform.clone();
        self.house_rules = source.house_rules.clone();
        self.prompt_overrides = source.prompt_overrides.clone();
        self.threat_model_sha256 = source.threat_model_sha256.clone();
        self.env_fingerprint = source.env_fingerprint.clone();
        self.target_git = source.target_git.clone();
        self.cli_args = source.cli_args.clone();
        self.loaded_modules = source.loaded_modules.clone();
        self.trace_malformed_lines = source.trace_malformed_lines;
        self
    }

    pub fn with_artifact(mut self, artifact: RunArtifact) -> Self {
        if let Some(artifact) = artifact.normalized() {
            if let Some(existing) = self
                .artifacts
                .iter_mut()
                .find(|existing| existing.path == artifact.path)
            {
                *existing = artifact;
            } else {
                self.artifacts.push(artifact);
            }
        }
        self
    }

    pub fn with_llm_calls(mut self, llm_calls: Vec<RunLlmCallAudit>) -> Self {
        self.llm_calls = llm_calls;
        self
    }

    pub fn with_trace_malformed_lines(mut self, malformed_lines: Option<usize>) -> Self {
        self.trace_malformed_lines = malformed_lines.filter(|count| *count > 0);
        self
    }

    pub fn with_house_rules(mut self, house_rules: Vec<RunHouseRuleFingerprint>) -> Self {
        self.house_rules = house_rules;
        self
    }

    pub fn with_prompt_overrides(
        mut self,
        prompt_overrides: Vec<RunPromptOverrideFingerprint>,
    ) -> Self {
        self.prompt_overrides = prompt_overrides;
        self
    }

    pub fn with_threat_model_sha256(mut self, threat_model_sha256: Option<String>) -> Self {
        self.threat_model_sha256 = non_empty_metadata(threat_model_sha256);
        self
    }

    pub fn with_env_fingerprint(mut self, env_fingerprint: Vec<RunEnvFingerprint>) -> Self {
        self.env_fingerprint = env_fingerprint;
        self
    }

    pub fn with_target_git(mut self, target_git: Option<RunTargetGitMetadata>) -> Self {
        self.target_git = target_git;
        self
    }

    pub fn with_cli_args(mut self, cli_args: Vec<String>) -> Self {
        self.cli_args = cli_args
            .into_iter()
            .map(|arg| arg.trim().to_string())
            .filter(|arg| !arg.is_empty())
            .collect();
        self
    }

    pub fn with_loaded_modules(mut self, loaded_modules: Vec<String>) -> Self {
        self.loaded_modules = Vec::new();
        for specifier in loaded_modules {
            let specifier = specifier.trim().to_string();
            if !specifier.is_empty() && !self.loaded_modules.contains(&specifier) {
                self.loaded_modules.push(specifier);
            }
        }
        self
    }
}

fn build_git_sha() -> Option<String> {
    non_empty_env(option_env!("KUZUSHI_GIT_SHA"))
}

fn build_git_branch() -> Option<String> {
    non_empty_env(option_env!("KUZUSHI_GIT_BRANCH"))
}

fn non_empty_env(value: Option<&str>) -> Option<String> {
    value.and_then(|value| non_empty_metadata(Some(value.to_string())))
}

fn non_empty_metadata(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn runtime_platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

// schema v2: adds module/feed metadata and optional LLM audit fields. All new
// fields are optional so older trace.jsonl files round-trip without rewrites.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RunTraceStep {
    pub n: usize,
    pub kind: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_step: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_hash: Option<String>,
}

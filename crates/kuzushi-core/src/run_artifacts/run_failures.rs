use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunFailures {
    pub run_id: String,
    pub status: String,
    pub failures: Vec<RunFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunFailure {
    pub tool: String,
    pub status: String,
    pub error: String,
    pub agent_thread_context: FailureToLlmContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FailureToLlmContext {
    #[serde(default)]
    pub failed_stage: String,
    #[serde(default)]
    pub cause: String,
    pub what_failed: String,
    pub artifacts_available: Vec<RunArtifact>,
    #[serde(default)]
    pub missing_artifacts: Vec<String>,
    pub allowed_proof_level: String,
    pub next_files_or_artifacts_to_inspect: Vec<String>,
    #[serde(default)]
    pub recovery_options: Vec<String>,
    #[serde(default)]
    pub fallback_prompt: String,
    pub claims_forbidden: Vec<String>,
}

const CANONICAL_FAILURE_ARTIFACTS: &[&str] = &[
    "run.json",
    "events.jsonl",
    "context.json",
    "attack-surface.json",
    "threat-model.json",
    "recommendations.json",
    "findings.json",
    "proof.json",
    "report.md",
];

const FOLLOW_UP_RUN_FILES: &[&str] = &[
    "failures.json",
    "result.json",
    "artifacts.json",
    "run.json",
    "summary.json",
];

const MAX_NEXT_FAILURE_PATHS: usize = 12;

pub fn write_run_failures(
    target: impl AsRef<Path>,
    run_id: &str,
    tool: &str,
    status: &str,
    error: &str,
    artifacts: &[RunArtifact],
) -> Result<RunArtifact> {
    let failure = RunFailure {
        tool: tool.to_string(),
        status: status.to_string(),
        error: error.to_string(),
        agent_thread_context: failure_to_llm_context(
            target.as_ref(),
            run_id,
            tool,
            error,
            artifacts,
        ),
    };
    let report = RunFailures {
        run_id: run_id.to_string(),
        status: status.to_string(),
        failures: vec![failure],
    };
    write_run_artifact_json(
        target,
        run_id,
        "failures.json",
        "failure handoff",
        &serde_json::to_value(report)?,
    )
}

pub fn load_run_failures(target: impl AsRef<Path>, run_id: &str) -> Result<RunFailures> {
    let path = run_dir(target.as_ref(), run_id).join("failures.json");
    let body = fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&body).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn load_run_failure_context(
    target: impl AsRef<Path>,
    run_id: &str,
) -> Result<Option<FailureToLlmContext>> {
    Ok(load_run_failures(target, run_id)?
        .failures
        .into_iter()
        .next()
        .map(|failure| failure.agent_thread_context))
}

pub fn output_with_run_fallback_context(
    target: impl AsRef<Path>,
    run_id: &str,
    output: Value,
) -> Value {
    let Ok(Some(context)) = load_run_failure_context(target, run_id) else {
        return output;
    };
    output_with_fallback_context(output, context)
}

fn output_with_fallback_context(mut output: Value, context: FailureToLlmContext) -> Value {
    let Value::Object(object) = &mut output else {
        return output;
    };
    if object.contains_key("fallback_context") || object.contains_key("fallbackContext") {
        return output;
    }
    if let Ok(context) = serde_json::to_value(context) {
        object.insert("fallback_context".to_string(), context);
    }
    output
}

fn failure_to_llm_context(
    target: &Path,
    run_id: &str,
    tool: &str,
    error: &str,
    artifacts: &[RunArtifact],
) -> FailureToLlmContext {
    let allowed_proof_level = "artifact-review-only; runtime verification did not run".to_string();
    let missing_artifacts = missing_failure_artifacts(target, run_id, artifacts);
    let claims_forbidden = forbidden_failure_claims();
    let recovery_options = failure_recovery_options(tool, &missing_artifacts);
    let fallback_prompt = failure_fallback_prompt(
        tool,
        error,
        &allowed_proof_level,
        &missing_artifacts,
        &claims_forbidden,
        &recovery_options,
    );
    FailureToLlmContext {
        failed_stage: tool.to_string(),
        cause: error.to_string(),
        what_failed: format!("{tool} did not complete successfully: {error}"),
        artifacts_available: artifacts.to_vec(),
        missing_artifacts,
        allowed_proof_level,
        next_files_or_artifacts_to_inspect: next_failure_artifacts(target, run_id, artifacts),
        recovery_options,
        fallback_prompt,
        claims_forbidden,
    }
}

fn next_failure_artifacts(target: &Path, run_id: &str, artifacts: &[RunArtifact]) -> Vec<String> {
    let mut paths = Vec::new();
    append_available_artifact_paths(&mut paths, artifacts);
    append_follow_up_run_files(&mut paths, target, run_id);
    paths
}

fn append_available_artifact_paths(paths: &mut Vec<String>, artifacts: &[RunArtifact]) {
    for artifact in artifacts {
        push_next_failure_path(paths, artifact.path.clone());
    }
}

fn append_follow_up_run_files(paths: &mut Vec<String>, target: &Path, run_id: &str) {
    let dir = run_dir(target, run_id);
    for leaf in FOLLOW_UP_RUN_FILES {
        push_next_failure_path(paths, dir.join(leaf).display().to_string());
    }
}

fn push_next_failure_path(paths: &mut Vec<String>, path: String) {
    if paths.len() >= MAX_NEXT_FAILURE_PATHS || paths.contains(&path) {
        return;
    }
    paths.push(path);
}

fn missing_failure_artifacts(target: &Path, run_id: &str, artifacts: &[RunArtifact]) -> Vec<String> {
    CANONICAL_FAILURE_ARTIFACTS
        .iter()
        .filter(|artifact| !failure_artifact_exists(target, run_id, artifacts, artifact))
        .map(|artifact| artifact.to_string())
        .collect()
}

fn failure_artifact_exists(
    target: &Path,
    run_id: &str,
    artifacts: &[RunArtifact],
    artifact: &str,
) -> bool {
    artifacts
        .iter()
        .any(|available| available.path.ends_with(artifact))
        || run_dir(target, run_id).join(artifact).exists()
}

fn failure_recovery_options(tool: &str, missing_artifacts: &[String]) -> Vec<String> {
    let mut options = vec![format!("Rerun {tool} after fixing the reported cause.")];
    if !missing_artifacts.is_empty() {
        options.push("Create or inspect the missing canonical artifacts before escalating.".into());
    }
    options.push("Keep follow-up claims at artifact-review-only proof level.".into());
    options
}

fn failure_fallback_prompt(
    tool: &str,
    error: &str,
    proof_level: &str,
    missing_artifacts: &[String],
    forbidden_claims: &[String],
    recovery_options: &[String],
) -> String {
    format!(
        "Continue the failed Kuzushi run for {tool}. Cause: {error}. Proof level: {proof_level}. Missing artifacts: {}. Forbidden claims: {}. Recovery options: {}.",
        compact_failure_list(missing_artifacts),
        compact_failure_list(forbidden_claims),
        compact_failure_list(recovery_options),
    )
}

fn compact_failure_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

fn forbidden_failure_claims() -> Vec<String> {
    [
        "success claim without explicit verification",
        "verified claim",
        "exploited claim",
        "fixed claim",
        "empirical proof claim",
        "runtime proof claim",
        "exploit proven",
        "fix confirmed",
        "false positive verdict",
        "no vulnerability verdict",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

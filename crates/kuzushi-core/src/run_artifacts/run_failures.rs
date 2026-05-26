use super::*;
use crate::artifact_contract::{
    canonical_run_artifact_spec, CanonicalRunArtifactSpec, CANONICAL_RUN_ARTIFACTS,
    OPTIONAL_RUN_ARTIFACTS, TOOL_INPUT_ARTIFACTS, TOOL_RESULT_ARTIFACTS,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunFailures {
    #[serde(alias = "run_id")]
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
    #[serde(alias = "agent_thread_context")]
    pub agent_thread_context: FailureToLlmContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FailureToLlmContext {
    #[serde(default, alias = "failed_stage")]
    pub failed_stage: String,
    #[serde(default, alias = "cause")]
    pub cause: String,
    #[serde(alias = "what_failed")]
    pub what_failed: String,
    #[serde(alias = "artifacts_available")]
    pub artifacts_available: Vec<RunArtifact>,
    #[serde(default, alias = "missing_artifacts")]
    pub missing_artifacts: Vec<String>,
    #[serde(alias = "allowed_proof_level")]
    pub allowed_proof_level: String,
    #[serde(alias = "next_files_or_artifacts_to_inspect")]
    pub next_files_or_artifacts_to_inspect: Vec<String>,
    #[serde(default, alias = "recovery_options")]
    pub recovery_options: Vec<String>,
    #[serde(default, alias = "fallback_prompt")]
    pub fallback_prompt: String,
    #[serde(alias = "claims_forbidden")]
    pub claims_forbidden: Vec<String>,
}

const LEGACY_FOLLOW_UP_RUN_FILES: &[&str] = &["summary.json"];

const MAX_AVAILABLE_FAILURE_ARTIFACTS: usize = 12;
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
    let spec = failure_artifact_spec();
    write_run_artifact_json(
        target,
        run_id,
        spec.leaf,
        spec.label,
        &serde_json::to_value(report)?,
    )
}

pub fn load_run_failures(target: impl AsRef<Path>, run_id: &str) -> Result<RunFailures> {
    let path = run_failure_artifact_path(target.as_ref(), run_id);
    let metadata = fs::metadata(&path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("Run failures artifact is not a file: {}", path.display());
    }
    let body =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value =
        serde_json::from_str(&body).with_context(|| format!("failed to parse {}", path.display()))?;
    if !value.is_object() {
        anyhow::bail!(
            "Run failures artifact is not a JSON object: {}",
            path.display()
        );
    }
    serde_json::from_value(value).with_context(|| format!("failed to parse {}", path.display()))
}

pub(crate) fn run_failure_artifact_path(target: &Path, run_id: &str) -> PathBuf {
    run_artifact_path(target, run_id, failure_artifact_spec().leaf)
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
    let next_artifacts = next_failure_artifacts(target, run_id, artifacts);
    let fallback_prompt = failure_fallback_prompt(
        tool,
        error,
        &allowed_proof_level,
        &missing_artifacts,
        &next_artifacts,
        &claims_forbidden,
        &recovery_options,
    );
    FailureToLlmContext {
        failed_stage: tool.to_string(),
        cause: error.to_string(),
        what_failed: format!("{tool} did not complete successfully: {error}"),
        artifacts_available: available_failure_artifacts(artifacts),
        missing_artifacts,
        allowed_proof_level,
        next_files_or_artifacts_to_inspect: next_artifacts,
        recovery_options,
        fallback_prompt,
        claims_forbidden,
    }
}

fn available_failure_artifacts(artifacts: &[RunArtifact]) -> Vec<RunArtifact> {
    artifacts
        .iter()
        .filter_map(RunArtifact::normalized)
        .take(MAX_AVAILABLE_FAILURE_ARTIFACTS)
        .collect()
}

fn next_failure_artifacts(target: &Path, run_id: &str, artifacts: &[RunArtifact]) -> Vec<String> {
    let mut paths = Vec::new();
    append_follow_up_run_files(&mut paths, target, run_id);
    append_available_artifact_paths(&mut paths, artifacts);
    paths
}

fn append_available_artifact_paths(paths: &mut Vec<String>, artifacts: &[RunArtifact]) {
    for artifact in artifacts {
        if let Some(artifact) = artifact.normalized() {
            push_next_failure_path(paths, artifact.path);
        }
    }
}

fn append_follow_up_run_files(paths: &mut Vec<String>, target: &Path, run_id: &str) {
    push_next_failure_path(
        paths,
        run_artifact_path(target, run_id, failure_artifact_spec().leaf)
            .display()
            .to_string(),
    );
    append_spec_follow_up_paths(paths, target, run_id, &TOOL_RESULT_ARTIFACTS);
    append_spec_follow_up_paths(paths, target, run_id, &TOOL_INPUT_ARTIFACTS);
    push_next_failure_path(
        paths,
        run_artifact_path(target, run_id, manifest_artifact_spec().leaf)
            .display()
            .to_string(),
    );
    push_next_failure_path(
        paths,
        run_artifact_path(target, run_id, run_metadata_artifact_spec().leaf)
            .display()
            .to_string(),
    );
    for leaf in LEGACY_FOLLOW_UP_RUN_FILES {
        push_next_failure_path(
            paths,
            run_artifact_path(target, run_id, leaf).display().to_string(),
        );
    }
    push_existing_follow_up_path(paths, target, run_id, report_artifact_spec().leaf);
    for spec in OPTIONAL_RUN_ARTIFACTS {
        push_existing_follow_up_path(paths, target, run_id, spec.leaf);
    }
}

fn append_spec_follow_up_paths(
    paths: &mut Vec<String>,
    target: &Path,
    run_id: &str,
    specs: &[CanonicalRunArtifactSpec],
) {
    for spec in specs {
        push_next_failure_path(
            paths,
            run_artifact_path(target, run_id, spec.leaf)
                .display()
                .to_string(),
        );
    }
}

fn push_existing_follow_up_path(paths: &mut Vec<String>, target: &Path, run_id: &str, leaf: &str) {
    let path = run_artifact_path(target, run_id, leaf);
    if path.is_file() {
        push_next_failure_path(paths, path.display().to_string());
    }
}

fn push_next_failure_path(paths: &mut Vec<String>, path: String) {
    if paths.len() >= MAX_NEXT_FAILURE_PATHS || paths.contains(&path) {
        return;
    }
    paths.push(path);
}

fn missing_failure_artifacts(target: &Path, run_id: &str, artifacts: &[RunArtifact]) -> Vec<String> {
    let failure_artifact = failure_artifact_spec().leaf;
    CANONICAL_RUN_ARTIFACTS
        .iter()
        .map(|spec| spec.leaf)
        .filter(|artifact| *artifact != failure_artifact)
        .filter(|artifact| !failure_artifact_exists(target, run_id, artifacts, artifact))
        .map(str::to_string)
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
        .any(|available| declared_failure_artifact_exists(target, run_id, available, artifact))
        || run_artifact_path(target, run_id, artifact).is_file()
}

fn declared_failure_artifact_exists(
    target: &Path,
    run_id: &str,
    available: &RunArtifact,
    artifact: &str,
) -> bool {
    if !available.path.ends_with(artifact) {
        return false;
    }
    failure_artifact_candidates(target, run_id, &available.path)
        .iter()
        .any(|path| path.is_file())
}

fn failure_artifact_candidates(target: &Path, run_id: &str, path: &str) -> Vec<PathBuf> {
    let declared = PathBuf::from(path);
    if declared.is_absolute() {
        return vec![declared];
    }
    vec![target.join(&declared), run_artifact_path(target, run_id, &declared)]
}

fn failure_recovery_options(tool: &str, missing_artifacts: &[String]) -> Vec<String> {
    let mut options = vec![format!("Rerun {tool} after fixing the reported cause.")];
    if !missing_artifacts.is_empty() {
        options.push("Create or inspect the missing canonical artifacts before escalating.".into());
    }
    options.push("Keep follow-up claims at artifact-review-only proof level.".into());
    options
}

fn failure_artifact_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("failures.json")
        .expect("failure handoff artifact must be in shared spec")
}

fn manifest_artifact_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("artifacts.json")
        .expect("artifact manifest must be in shared spec")
}

fn run_metadata_artifact_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("run.json").expect("run metadata artifact must be in shared spec")
}

fn report_artifact_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("report.md").expect("report artifact must be in shared spec")
}

fn failure_fallback_prompt(
    tool: &str,
    error: &str,
    proof_level: &str,
    missing_artifacts: &[String],
    next_artifacts: &[String],
    forbidden_claims: &[String],
    recovery_options: &[String],
) -> String {
    format!(
        "Continue the failed Kuzushi run for {tool}. Cause: {error}. Proof level: {proof_level}. Missing artifacts: {}. Inspect next: {}. Forbidden claims: {}. Recovery options: {}.",
        compact_failure_list(missing_artifacts),
        compact_failure_list(next_artifacts),
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

use super::*;
use crate::artifact_contract::{
    canonical_run_artifact_spec, CanonicalRunArtifactSpec, CANONICAL_RUN_ARTIFACTS,
    OPTIONAL_RUN_ARTIFACTS, TOOL_INPUT_ARTIFACTS, TOOL_RESULT_ARTIFACTS,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunFailures {
    pub run_id: String,
    pub status: String,
    pub failures: Vec<RunFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunFailure {
    pub tool: String,
    pub status: String,
    pub error: String,
    pub agent_thread_context: FailureToLlmContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureToLlmContext {
    pub failed_stage: String,
    pub cause: String,
    pub what_failed: String,
    pub artifacts_available: Vec<RunArtifact>,
    pub missing_artifacts: Vec<String>,
    pub allowed_proof_level: String,
    pub next_files_or_artifacts_to_inspect: Vec<String>,
    pub recovery_options: Vec<String>,
    pub fallback_prompt: String,
    pub claims_forbidden: Vec<String>,
}

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
    // Failure text is persisted verbatim into a durable artifact; redact
    // credential-shaped content (Authorization headers, api keys echoed by
    // provider or wrapper errors) before it lands on disk.
    let error = crate::session_transcript::redaction::redact_text(error);
    let failure = RunFailure {
        tool: tool.to_string(),
        status: status.to_string(),
        error: error.to_string(),
        agent_thread_context: failure_to_llm_context(
            target.as_ref(),
            run_id,
            tool,
            &error,
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
    let (path, body) = read_run_artifact_text(target, run_id, failure_artifact_spec().leaf)
        .require("Run failures artifact")?;
    let value: Value = serde_json::from_str(&body)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if !value.is_object() {
        anyhow::bail!(
            "Run failures artifact is not a JSON object: {}",
            path.display()
        );
    }
    serde_json::from_value(value).map_err(|error| {
        anyhow::anyhow!(
            "Run failures artifact is not canonical: {error}: {}",
            path.display()
        )
    })
}

pub(crate) fn run_failure_artifact_path(target: &Path, run_id: &str) -> Result<PathBuf> {
    checked_run_artifact_path(target, run_id, failure_artifact_spec().leaf)
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
    if object.contains_key("fallback_context") {
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
        artifacts_available: available_failure_artifacts(target, run_id, artifacts),
        missing_artifacts,
        allowed_proof_level,
        next_files_or_artifacts_to_inspect: next_artifacts,
        recovery_options,
        fallback_prompt,
        claims_forbidden,
    }
}

fn available_failure_artifacts(
    target: &Path,
    run_id: &str,
    artifacts: &[RunArtifact],
) -> Vec<RunArtifact> {
    artifacts
        .iter()
        .filter_map(|artifact| contained_failure_artifact(target, run_id, artifact))
        .take(MAX_AVAILABLE_FAILURE_ARTIFACTS)
        .collect()
}

fn next_failure_artifacts(target: &Path, run_id: &str, artifacts: &[RunArtifact]) -> Vec<String> {
    let mut paths = Vec::new();
    append_follow_up_run_files(&mut paths, target, run_id);
    append_available_artifact_paths(&mut paths, target, run_id, artifacts);
    paths
}

fn append_available_artifact_paths(
    paths: &mut Vec<String>,
    target: &Path,
    run_id: &str,
    artifacts: &[RunArtifact],
) {
    for artifact in artifacts {
        if let Some(artifact) = contained_failure_artifact(target, run_id, artifact) {
            push_next_failure_path(paths, artifact.path);
        }
    }
}

fn contained_failure_artifact(
    target: &Path,
    run_id: &str,
    artifact: &RunArtifact,
) -> Option<RunArtifact> {
    let artifact = artifact.normalized()?;
    (!failure_artifact_candidates(target, run_id, &artifact.path).is_empty()).then_some(artifact)
}

fn append_follow_up_run_files(paths: &mut Vec<String>, target: &Path, run_id: &str) {
    append_safe_follow_up_path(paths, target, run_id, failure_artifact_spec().leaf);
    append_spec_follow_up_paths(paths, target, run_id, &TOOL_RESULT_ARTIFACTS);
    append_spec_follow_up_paths(paths, target, run_id, &TOOL_INPUT_ARTIFACTS);
    append_safe_follow_up_path(paths, target, run_id, manifest_artifact_spec().leaf);
    append_safe_follow_up_path(paths, target, run_id, run_metadata_artifact_spec().leaf);
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
        append_safe_follow_up_path(paths, target, run_id, spec.leaf);
    }
}

fn append_safe_follow_up_path(paths: &mut Vec<String>, target: &Path, run_id: &str, leaf: &str) {
    if let Ok(path) = checked_run_artifact_path(target, run_id, leaf) {
        push_next_failure_path(paths, path.display().to_string());
    }
}

fn push_existing_follow_up_path(paths: &mut Vec<String>, target: &Path, run_id: &str, leaf: &str) {
    let Ok(path) = checked_run_artifact_path(target, run_id, leaf) else {
        return;
    };
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

fn missing_failure_artifacts(
    target: &Path,
    run_id: &str,
    artifacts: &[RunArtifact],
) -> Vec<String> {
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
        || checked_run_artifact_path(target, run_id, artifact).is_ok_and(|path| path.is_file())
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
        return contained_absolute_artifact(target, &declared)
            .into_iter()
            .collect();
    }
    let Ok(artifact_path) = ArtifactPath::parse(&declared) else {
        return Vec::new();
    };
    let mut candidates =
        crate::workspace::validated_workspace_descendant(target, artifact_path.as_path())
            .into_iter()
            .collect::<Vec<_>>();
    if let Ok(run_path) = checked_run_artifact_path(target, run_id, artifact_path.as_path()) {
        if !candidates.contains(&run_path) {
            candidates.push(run_path);
        }
    }
    candidates
}

fn contained_absolute_artifact(target: &Path, declared: &Path) -> Option<PathBuf> {
    let root = fs::canonicalize(target).ok()?;
    let relative = declared
        .strip_prefix(target)
        .or_else(|_| declared.strip_prefix(&root))
        .ok()?;
    crate::workspace::validated_workspace_descendant(&root, relative).ok()
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
    canonical_run_artifact_spec("artifacts.json").expect("artifact manifest must be in shared spec")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_failure_text_is_redacted() {
        let tmp = tempfile::tempdir().unwrap();
        write_run_failures(
            tmp.path(),
            "run-redact",
            "demo:tool",
            "failed",
            "provider rejected request: Authorization: Bearer sk-live-secret-000000 retry later",
            &[],
        )
        .unwrap();

        let report = load_run_failures(tmp.path(), "run-redact").unwrap();
        let error = &report.failures[0].error;
        assert!(!error.contains("sk-live-secret"), "{error}");
        assert!(error.contains("[REDACTED]"), "{error}");
    }
}

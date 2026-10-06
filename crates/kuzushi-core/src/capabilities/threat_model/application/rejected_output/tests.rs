use super::*;
use crate::runtime::{AgentQueryResponse, TriageRequest};
use std::sync::Mutex;

struct InvalidRuntime(Mutex<usize>);

impl AgentRuntime for InvalidRuntime {
    fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
        *self.0.lock().unwrap() += 1;
        Ok(AgentQueryResponse {
            text: "LABELED_REJECTED_OUTPUT not JSON".into(),
            ..Default::default()
        })
    }
    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<crate::TriageOutcome> {
        unreachable!()
    }
}

fn input(root: &Path, enabled: bool) -> BuildInput {
    BuildInput {
        roots: ThreatModelBuildRoots {
            workspace_root: root.into(),
            analysis_root: root.into(),
            scope: None,
        },
        pipeline: "single".into(),
        mode: "build".into(),
        methodology: "stride".into(),
        model: "openai-codex:gpt-5.5".into(),
        max_output_tokens: 1024,
        save_rejected_output: enabled,
        ..Default::default()
    }
}

fn context<'a>(
    config: &'a crate::V2Config,
    trace: &'a crate::run_artifacts::TraceHandle,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        trace: Some(trace),
        workspace: None,
        findings_store: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

fn reject(input: &BuildInput, ctx: &ToolExecutionContext<'_>) -> anyhow::Error {
    let runtime = InvalidRuntime(Mutex::new(0));
    let error = super::super::build_threat_model::query_threat_model_document(
        &runtime,
        ctx,
        BuildFlavor::ThreatModel,
        "build",
        input,
        "Labeled source-only fixture".into(),
    )
    .unwrap_err();
    assert_eq!(
        *runtime.0.lock().unwrap(),
        2,
        "retention starts no model request"
    );
    error
}

#[test]
fn explicit_retention_publishes_bounded_private_evidence_without_accepting_context() {
    let root = tempfile::tempdir().unwrap();
    let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), "rejected-run");
    let config = crate::V2Config::default();
    let ctx = context(&config, &trace);
    let error = reject(&input(root.path(), true), &ctx);
    assert!(error.to_string().contains(LEAF));
    assert!(!error.to_string().contains("LABELED_REJECTED_OUTPUT"));
    let (_, body) = crate::run_artifacts::read_run_artifact_text(root.path(), "rejected-run", LEAF)
        .require("Rejected output")
        .unwrap();
    assert!(body.contains("LABELED_REJECTED_OUTPUT"));
    assert!(
        body.contains("Initial parse/validation failure")
            && body.contains("Repair parse/validation failure")
    );
    assert!(body.len() <= 24 * 1024 + 1);
    let artifacts = crate::run_artifacts::load_run_artifacts(root.path(), "rejected-run").unwrap();
    assert!(artifacts.iter().any(|artifact| artifact.path == LEAF));
    assert!(!root
        .path()
        .join(".kuzushi/threat-models/manifest.json")
        .exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = root.path().join(".kuzushi/v3/runs/rejected-run").join(LEAF);
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn default_rejection_has_safe_error_text_and_keeps_raw_output_out_of_artifacts() {
    let root = tempfile::tempdir().unwrap();
    let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), "default-run");
    let config = crate::V2Config::default();
    let error = reject(&input(root.path(), false), &context(&config, &trace));
    assert!(!error.to_string().contains("LABELED_REJECTED_OUTPUT"));
    assert!(!root
        .path()
        .join(".kuzushi/v3/runs/default-run")
        .join(LEAF)
        .exists());
}

#[test]
fn incompatible_modes_missing_runs_and_other_workspaces_fail_before_inference() {
    for pipeline in ["staged", "deterministic"] {
        assert!(
            validate_requested_mode(&json!({"saveRejectedOutput":true,"pipeline":pipeline}))
                .is_err()
        );
    }
    assert!(validate_requested_mode(&json!({"saveRejectedOutput":true,"mode":"refine"})).is_err());
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let config = crate::V2Config::default();
    let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), "missing-run");
    let mut missing = context(&config, &trace);
    missing.trace = None;
    assert!(validate(&input(root.path(), true), &missing).is_err());
    let trace = crate::run_artifacts::TraceHandle::jsonl(other.path(), "wrong-run");
    assert!(validate(&input(root.path(), true), &context(&config, &trace)).is_err());
    assert!(validate(&input(root.path(), false), &context(&config, &trace)).is_ok());
}

#[test]
fn unrelated_provider_errors_never_persist_authentication_material() {
    let root = tempfile::tempdir().unwrap();
    let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), "provider-error");
    let config = crate::V2Config::default();
    let error = retain(
        &input(root.path(), true),
        &context(&config, &trace),
        anyhow::anyhow!("LABELED_PROVIDER_SECRET"),
    );
    assert_eq!(error.to_string(), "LABELED_PROVIDER_SECRET");
    assert!(!root
        .path()
        .join(".kuzushi/v3/runs/provider-error")
        .join(LEAF)
        .exists());
}

#[cfg(unix)]
#[test]
fn rejected_output_symlink_cannot_write_outside_the_run() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), "outside sentinel").unwrap();
    let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), "symlink-run");
    let parent = root.path().join(".kuzushi/v3/runs/symlink-run");
    std::fs::create_dir_all(&parent).unwrap();
    std::os::unix::fs::symlink(outside.path(), parent.join(LEAF)).unwrap();
    let config = crate::V2Config::default();
    let error = reject(&input(root.path(), true), &context(&config, &trace));
    assert!(error.to_string().contains("could not be saved"));
    assert!(!error.to_string().contains("LABELED_REJECTED_OUTPUT"));
    assert_eq!(
        std::fs::read_to_string(outside.path()).unwrap(),
        "outside sentinel"
    );
}

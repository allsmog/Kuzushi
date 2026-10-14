//! Bounded, descriptive citation inspection over the authoritative finding ledger.
use crate::findings::{Finding, FindingStore, GroundingStatus};
use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
mod audit;
#[cfg(test)]
#[path = "findings_ground/tests.rs"]
mod contract_tests;
mod limits;
mod pass;
mod presentation;
mod source;

pub fn execute_findings_ground(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "findings:ground",
        ))?;
    let store = ctx
        .findings_store
        .context("findings:ground requires the findings store")?;
    let limits = limits::GroundingLimits::from_input(input)?;
    let git = git_inspection(workspace.root());
    let pass = pass::inspect_candidates(ctx, store, workspace.root(), limits, &git)?;
    let output = presentation::output(&pass);
    let data = pass_data(&pass, workspace.root(), limits, &git);
    if pass.partial() {
        return Ok(crate::module_result::partial_output_result(
            output.clone(),
            output,
            presentation::warnings(&pass)
                .into_iter()
                .map(Value::String)
                .collect(),
            data,
        ));
    }
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        data,
    ))
}

fn pass_data(
    pass: &pass::GroundingPass,
    root: &std::path::Path,
    limits: limits::GroundingLimits,
    git: &Value,
) -> Value {
    json!({
        "checked":pass.checked,"counts":pass.counts,"newlyDrifted":pass.newly_drifted,
        "revision":git["sha"],"target":root,"git":git,"inspections":pass.inspections,
        "coverage":{"selected":pass.selected,"excluded":pass.excluded,"hasMoreCandidates":pass.has_more,
            "maxFindings":limits.findings,"maxBytesPerFile":limits.per_file,"maxTotalBytes":limits.total_bytes,
            "capturedBytes":pass.bytes,"reservedReadBytes":pass.reserved_bytes,"stopReason":pass.stopped,"complete":!pass.partial(),
            "meaning":"Citation checks for the selected ledger window. This does not establish repository scan coverage or finding validity."},
        "findingVerdictsChanged":false,
    })
}

fn git_inspection(root: &std::path::Path) -> Value {
    crate::workspace::target_git_metadata(root)
        .map(|metadata| json!({"sha":metadata.sha,"branch":metadata.branch,"dirty":metadata.dirty}))
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::import::import_ledger_jsonl;
    use crate::modules::ExecutionAuthorization;
    use crate::workspace::WorkspaceTarget;
    use crate::V2Config;

    #[test]
    fn deleted_file_is_flagged_not_retired_and_repeat_runs_stay_quiet() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/app.py"), "open(path)\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let ledger = temp.path().join("ledger.jsonl");
        std::fs::write(
            &ledger,
            r#"{"file":"src/app.py","line":1,"title":"path traversal (CWE-22)","severity":"P1"}"#,
        )
        .unwrap();
        import_ledger_jsonl(&workspace, &ledger, "external").unwrap();
        std::fs::remove_file(temp.path().join("src/app.py")).unwrap();

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: ExecutionAuthorization::default(),
        };

        let result = execute_findings_ground(&json!({}), &ctx).unwrap();
        let data = &result["data"];
        assert_eq!(data["counts"]["file_missing"], json!(1));
        assert_eq!(data["newlyDrifted"].as_array().unwrap().len(), 1);
        let finding = store.list_findings(10).unwrap().pop().unwrap();
        assert!(!finding.suppressed, "grounding never retires");

        // Second pass: same stale anchor, no second audit event.
        let second = execute_findings_ground(&json!({}), &ctx).unwrap();
        assert_eq!(second["data"]["newlyDrifted"].as_array().unwrap().len(), 0);
        assert_eq!(second["data"]["counts"]["file_missing"], json!(1));
    }
}

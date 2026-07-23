//! `findings:ground` — re-run import grounding over the open corpus.
//!
//! Runtime-free and descriptive: every open finding's citation is re-checked
//! against the target tree at the current revision, per-status counts are
//! reported, and each finding whose anchor *newly* went stale gets one audit
//! event. Grounding never retires or re-verdicts a finding — a missing file
//! is a flag for triage honesty, not proof the bug is gone.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::findings::{
    ground_finding_location, Finding, FindingStore, GroundingStatus,
};
use crate::modules::ToolExecutionContext;

const DEFAULT_GROUND_LIMIT: usize = 500;

pub fn execute_findings_ground(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "findings:ground",
        ))?;
    let store = ctx
        .findings_store
        .context("findings:ground requires the findings store")?;
    let limit = ground_limit(input)?;
    let revision = crate::workspace::target_git_metadata(workspace.root()).map(|meta| meta.sha);
    let pass = ground_open_findings(store, workspace.root(), revision.as_deref(), limit)?;
    let output = ground_output(pass.checked, &pass.counts, pass.newly_drifted.len());
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "checked": pass.checked,
            "counts": pass.counts,
            "newlyDrifted": pass.newly_drifted,
            "revision": revision,
        }),
    ))
}

struct GroundingPass {
    checked: usize,
    counts: BTreeMap<&'static str, usize>,
    newly_drifted: Vec<String>,
}

fn ground_open_findings(
    store: &FindingStore,
    root: &std::path::Path,
    revision: Option<&str>,
    limit: usize,
) -> Result<GroundingPass> {
    let rekeyed = store.rekeyed_stable_keys()?;
    let mut pass = GroundingPass {
        checked: 0,
        counts: BTreeMap::new(),
        newly_drifted: Vec::new(),
    };
    let open = store
        .list_all_findings()?
        .into_iter()
        .filter(|finding| !finding.suppressed && !rekeyed.contains(&stable_key(finding)))
        .take(limit);
    for finding in open {
        pass.checked += 1;
        let status = ground_one(root, &finding, revision);
        *pass.counts.entry(status.label()).or_default() += 1;
        if anchor_newly_stale(&finding, &status) && !already_audited(store, &finding) {
            record_drift_audit(store, &finding, &status);
            pass.newly_drifted.push(finding.fingerprint.clone());
        }
    }
    Ok(pass)
}

fn ground_limit(input: &Value) -> Result<usize> {
    let Some(value) = input.get("limit") else {
        return Ok(DEFAULT_GROUND_LIMIT);
    };
    value
        .as_u64()
        .map(|count| count as usize)
        .context("findings:ground: limit must be a non-negative integer")
}

fn stable_key(finding: &Finding) -> String {
    finding
        .identity_id
        .clone()
        .unwrap_or_else(|| finding.fingerprint.clone())
}

/// Re-check the finding's anchor: the first disk-verifiable evidence snippet
/// sharpens the check; findings with only reasoning evidence ground on the
/// file/line alone.
fn ground_one(
    root: &std::path::Path,
    finding: &Finding,
    revision: Option<&str>,
) -> GroundingStatus {
    let snippet = finding
        .evidence
        .iter()
        .find(|item| {
            !item.kind.trim().eq_ignore_ascii_case("reasoning")
                && item.request_blob.is_none()
                && !item.snippet.trim().is_empty()
        })
        .map(|item| item.snippet.as_str())
        .unwrap_or("");
    ground_finding_location(root, &finding.file_path, finding.start_line, snippet, revision)
}

/// A drift audit event fires only on the transition into a stale anchor:
/// findings already stamped stale at import stay quiet.
fn anchor_newly_stale(finding: &Finding, status: &GroundingStatus) -> bool {
    let stale_now = matches!(
        status,
        GroundingStatus::LineDrift { .. } | GroundingStatus::FileMissing { .. }
    );
    let stale_before = matches!(
        finding.grounding,
        Some(GroundingStatus::LineDrift { .. }) | Some(GroundingStatus::FileMissing { .. })
    );
    stale_now && !stale_before
}

/// Repeated `findings:ground` runs stay quiet for anchors that already
/// carry a grounding audit event.
fn already_audited(store: &FindingStore, finding: &Finding) -> bool {
    use rusqlite::OptionalExtension;
    store
        .conn
        .query_row(
            "select 1 from audit_events
              where actor = 'findings:ground'
                and subject = 'grounding'
                and stable_fp = ?1
              limit 1",
            [stable_key(finding)],
            |_| Ok(()),
        )
        .optional()
        .ok()
        .flatten()
        .is_some()
}

fn record_drift_audit(store: &FindingStore, finding: &Finding, status: &GroundingStatus) {
    let Some(finding_id) = finding.id else {
        return;
    };
    let _ = store.record_finding_audit_event(
        finding_id,
        "findings:ground",
        "grounding",
        format!("citation anchor went stale: {}", status.label()),
        serde_json::to_value(status).unwrap_or(Value::Null),
    );
}

fn ground_output(checked: usize, counts: &BTreeMap<&'static str, usize>, drifted: usize) -> String {
    let breakdown = counts
        .iter()
        .map(|(label, count)| format!("{label}={count}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "findings:ground checked {checked} finding(s): {breakdown}{}",
        if drifted > 0 {
            format!(" — {drifted} newly drifted (audited, not retired)")
        } else {
            String::new()
        }
    )
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

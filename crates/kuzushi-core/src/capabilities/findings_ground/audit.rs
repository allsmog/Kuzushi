use super::*;
use rusqlite::OptionalExtension;

pub(super) fn audit_drift(
    store: &FindingStore,
    finding: &Finding,
    status: &GroundingStatus,
    source: &Value,
    git: &Value,
) -> Result<bool> {
    if !anchor_newly_stale(finding, status) {
        return Ok(false);
    }
    let mut details = serde_json::to_value(status)?;
    details["source"] = source.clone();
    details["git"] = git.clone();
    details["inspectionKey"] = json!(crate::identity::hash_parts(
        "citation-inspection",
        &[serde_json::to_vec(&details)?.as_slice()]
    )
    .to_string());
    if already_audited(store, finding, &details)? {
        return Ok(false);
    }
    let id = finding
        .id
        .context("Cannot audit a citation without its finding generation")?;
    store.record_finding_audit_event(
        id,
        "findings:ground",
        "grounding",
        format!(
            "Citation inspection: {}. Finding verdict unchanged.",
            status.label()
        ),
        details,
    )?;
    Ok(true)
}

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

fn already_audited(store: &FindingStore, finding: &Finding, details: &Value) -> Result<bool> {
    let key = finding
        .identity_id
        .as_deref()
        .unwrap_or(&finding.fingerprint);
    let found = store.conn.query_row(
        "select 1 from audit_events where actor='findings:ground' and subject='grounding' and stable_fp=?1 and json_extract(payload_json,'$.details.inspectionKey')=?2 limit 1",
        rusqlite::params![key,details["inspectionKey"].as_str()], |_| Ok(()),
    ).optional().context("Could not inspect prior citation audits")?;
    Ok(found.is_some())
}

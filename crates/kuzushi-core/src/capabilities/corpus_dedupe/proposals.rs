//! Model groups become reviewable relationships, never finding verdicts.
use super::*;
use crate::findings::{FindingRelationshipKind, FindingStore};

pub(super) fn record_groups(
    store: &FindingStore,
    ctx: &ToolExecutionContext<'_>,
    groups: &[DuplicateGroup],
    by_fingerprint: &BTreeMap<&str, &Finding>,
    dry_run: bool,
) -> Result<link::LinkReport> {
    let mut report = link::LinkReport {
        dry_run,
        ..Default::default()
    };
    for group in groups {
        record_group(store, ctx, group, by_fingerprint, &mut report)?;
    }
    Ok(report)
}

fn record_group(
    store: &FindingStore,
    ctx: &ToolExecutionContext<'_>,
    group: &DuplicateGroup,
    findings: &BTreeMap<&str, &Finding>,
    report: &mut link::LinkReport,
) -> Result<()> {
    let canonical = findings
        .get(group.canonical_fingerprint.as_str())
        .context("dedupe canonical finding is unavailable")?;
    for fingerprint in &group.duplicate_fingerprints {
        ctx.ensure_active()?;
        let duplicate = findings
            .get(fingerprint.as_str())
            .context("dedupe member is unavailable")?;
        if report.dry_run {
            report.proposed += 1;
            continue;
        }
        let record = store.propose_recorded_finding_relationship(
            duplicate,
            canonical,
            FindingRelationshipKind::Duplicate,
            &group.root_cause_summary,
            Some(group.confidence),
        )?;
        report.proposed += 1;
        report.relationship_ids.push(record.id);
    }
    Ok(())
}

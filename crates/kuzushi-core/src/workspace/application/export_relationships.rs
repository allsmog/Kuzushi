//! Include every current relationship touching each exported durable finding.
use super::export_projection_model::WorkspaceFindingExportRecord;
use super::*;
use crate::findings::FindingRelationship;

pub(super) fn attach_relationships(
    store: &FindingStore,
    findings: &[Finding],
    records: &mut [WorkspaceFindingExportRecord],
) -> Result<()> {
    anyhow::ensure!(
        findings.len() == records.len(),
        "relationship export findings do not match records"
    );
    for (finding, record) in findings.iter().zip(records) {
        record.relationships =
            relationships_for_finding(store, finding.id.context("exported finding id missing")?)?;
    }
    Ok(())
}

fn relationships_for_finding(store: &FindingStore, id: i64) -> Result<Vec<FindingRelationship>> {
    let mut rows = Vec::new();
    let mut offset = 0;
    loop {
        let page = store.finding_relationships(Some(id), 200, offset)?;
        rows.extend(page.rows);
        if !page.has_more {
            return Ok(rows);
        }
        offset += 200;
    }
}

#[cfg(test)]
mod tests;

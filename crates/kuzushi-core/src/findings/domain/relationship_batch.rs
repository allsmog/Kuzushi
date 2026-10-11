use super::*;

pub(crate) const FINDING_RELATIONSHIP_BATCH_SUBJECT: &str = "finding-relationship-batch-v1";

pub(crate) fn validate_relationship_selection(records: &[FindingRelationship]) -> Result<()> {
    anyhow::ensure!(
        (1..=50).contains(&records.len()),
        "Choose between 1 and 50 relationships"
    );
    let mut ids = std::collections::BTreeSet::new();
    for record in records {
        record.validate()?;
        anyhow::ensure!(
            ids.insert(&record.id),
            "Relationship selection contains duplicate ids"
        );
    }
    Ok(())
}

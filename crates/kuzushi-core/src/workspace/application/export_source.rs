use super::export_projection_model::WorkspaceFindingExportRecord;
use super::*;
use crate::findings::RecordedObservationSource;
use std::collections::{BTreeSet, HashMap};

pub(super) fn attach_observation_sources(
    store: &FindingStore,
    findings: &[Finding],
    records: &mut [WorkspaceFindingExportRecord],
) -> Result<()> {
    anyhow::ensure!(
        findings.len() == records.len(),
        "Source export findings do not match records"
    );
    let mut cache = HashMap::new();
    for (finding, record) in findings.iter().zip(records) {
        record.provenance.observation_source = cached_source(
            store,
            &mut cache,
            finding
                .id
                .context("Exported finding generation is missing")?,
        )?;
        record.provenance.relationship_sources =
            relationship_sources(store, &mut cache, &record.relationships)?;
    }
    Ok(())
}

pub(super) fn csv_source_fields(record: &WorkspaceFindingExportRecord) -> [String; 3] {
    [
        json!(record.provenance.run_git).to_string(),
        json!(record.provenance.observation_source).to_string(),
        json!(record.provenance.relationship_sources).to_string(),
    ]
}

type SourceCache = HashMap<i64, Option<RecordedObservationSource>>;

fn cached_source(
    store: &FindingStore,
    cache: &mut SourceCache,
    id: i64,
) -> Result<Option<RecordedObservationSource>> {
    if let std::collections::hash_map::Entry::Vacant(entry) = cache.entry(id) {
        entry.insert(store.recorded_observation_source(id)?);
    }
    Ok(cache.get(&id).cloned().flatten())
}

fn relationship_sources(
    store: &FindingStore,
    cache: &mut SourceCache,
    records: &[crate::findings::FindingRelationship],
) -> Result<Vec<RecordedObservationSource>> {
    let ids = records
        .iter()
        .flat_map(|record| [record.from.finding_id, record.to.finding_id])
        .collect::<BTreeSet<_>>();
    ids.into_iter()
        .map(|id| {
            cached_source(store, cache, id)?.with_context(|| {
                format!("Recorded relationship source generation {id} is unavailable")
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;

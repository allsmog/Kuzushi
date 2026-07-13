use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArtifactRefreshReport {
    pub indexed: usize,
    pub unchanged: usize,
    pub partial: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceIndexReport {
    pub indexed: usize,
    pub unchanged: usize,
    pub partial: bool,
}

pub(crate) fn refresh_workspace_artifacts(
    workspace: &WorkspaceTarget,
) -> Result<ArtifactRefreshReport> {
    let store = ArtifactKnowledgeStore::open(workspace)?;
    let candidates = refresh_artifact_record_candidates(workspace)?;
    let sources = index_artifact_sources(&store, workspace, candidates.paths)?;
    let findings = store.refresh_findings_database(workspace)?;
    Ok(ArtifactRefreshReport {
        indexed: sources.indexed + findings.indexed,
        unchanged: sources.unchanged,
        partial: candidates.partial || sources.partial || findings.partial,
    })
}

pub(crate) fn index_artifact_sources(
    store: &ArtifactKnowledgeStore,
    workspace: &WorkspaceTarget,
    source_paths: Vec<String>,
) -> Result<SourceIndexReport> {
    let mut report = SourceIndexReport::default();
    for source_path in source_paths {
        match index_artifact_source(store, workspace, source_path)? {
            SourceIndexOutcome::Indexed => report.indexed += 1,
            SourceIndexOutcome::Unchanged => report.unchanged += 1,
            SourceIndexOutcome::ChangedDuringRead => {
                report.indexed += 1;
                report.partial = true;
            }
            SourceIndexOutcome::Missing => report.partial = true,
        }
    }
    Ok(report)
}

enum SourceIndexOutcome {
    Indexed,
    Unchanged,
    ChangedDuringRead,
    Missing,
}

fn index_artifact_source(
    store: &ArtifactKnowledgeStore,
    workspace: &WorkspaceTarget,
    source_path: String,
) -> Result<SourceIndexOutcome> {
    let Some(before) = SourceSignature::inspect(workspace, &source_path)? else {
        return Ok(SourceIndexOutcome::Missing);
    };
    if store.source_is_current(&source_path, before)? {
        return Ok(SourceIndexOutcome::Unchanged);
    }
    let Some(record) = workspace_artifact_record(workspace, source_path.clone())? else {
        return Ok(SourceIndexOutcome::Missing);
    };
    let after = SourceSignature::inspect(workspace, &source_path)?;
    if after != Some(before) {
        store.upsert_record(&record)?;
        return Ok(SourceIndexOutcome::ChangedDuringRead);
    }
    store.upsert_record_with_signature(&record, Some(before))?;
    Ok(SourceIndexOutcome::Indexed)
}

use super::corpus::CorpusFindingRow;
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

/// Where a dedup cluster lives across two revisions of one target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingLead {
    /// Only on the head revision: introduced there (or newly detected).
    BranchDelta,
    /// Only on the base revision: fixed on head, or a backport gap if the
    /// base is the older maintenance line.
    BackportGap,
    /// Present on both revisions.
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffFindingEntry {
    pub cluster_id: String,
    pub lead: FindingLead,
    pub file: String,
    pub class: String,
    pub severity: String,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffFindingsReport {
    pub target_id: String,
    pub base_sha: String,
    pub head_sha: String,
    pub entries: Vec<DiffFindingEntry>,
}

/// Join the corpus across two revisions of one target by dedup cluster —
/// never by the free-text identity, which churns run-to-run.
pub fn diff_findings(
    fleet_dir: &Path,
    target_id: &str,
    base_sha: &str,
    head_sha: &str,
) -> Result<DiffFindingsReport> {
    let rows = super::corpus::query_corpus_rows(fleet_dir, None, None, usize::MAX)?;
    let base = revision_rows(&rows, target_id, base_sha);
    let head = revision_rows(&rows, target_id, head_sha);
    Ok(DiffFindingsReport {
        target_id: target_id.to_string(),
        base_sha: base_sha.to_string(),
        head_sha: head_sha.to_string(),
        entries: labeled_entries(&base, &head),
    })
}

fn revision_rows<'rows>(
    rows: &'rows [CorpusFindingRow],
    target_id: &str,
    sha: &str,
) -> Vec<&'rows CorpusFindingRow> {
    rows.iter()
        .filter(|row| row.target_id == target_id && row.revision_sha.as_deref() == Some(sha))
        .collect()
}

fn labeled_entries(
    base: &[&CorpusFindingRow],
    head: &[&CorpusFindingRow],
) -> Vec<DiffFindingEntry> {
    let base_clusters: BTreeSet<&str> =
        base.iter().map(|row| row.cluster_id.as_str()).collect();
    let head_clusters: BTreeSet<&str> =
        head.iter().map(|row| row.cluster_id.as_str()).collect();
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for row in head.iter().chain(base.iter()) {
        if !seen.insert(row.cluster_id.as_str()) {
            continue;
        }
        entries.push(entry(row, lead_for(&row.cluster_id, &base_clusters, &head_clusters)));
    }
    entries
}

fn lead_for(
    cluster_id: &str,
    base_clusters: &BTreeSet<&str>,
    head_clusters: &BTreeSet<&str>,
) -> FindingLead {
    match (base_clusters.contains(cluster_id), head_clusters.contains(cluster_id)) {
        (true, true) => FindingLead::Both,
        (false, true) => FindingLead::BranchDelta,
        (true, false) | (false, false) => FindingLead::BackportGap,
    }
}

fn entry(row: &CorpusFindingRow, lead: FindingLead) -> DiffFindingEntry {
    DiffFindingEntry {
        cluster_id: row.cluster_id.clone(),
        lead,
        file: row.file.clone(),
        class: row.class.clone(),
        severity: row.severity.clone(),
        title: row.title.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(cluster: &str, sha: &str) -> CorpusFindingRow {
        CorpusFindingRow {
            target_id: "t1".to_string(),
            fingerprint: format!("{cluster}@{sha}"),
            file: "src/a.c".to_string(),
            line: 100,
            class: "mem-oob-write".to_string(),
            severity: "high".to_string(),
            cluster_id: cluster.to_string(),
            revision_sha: Some(sha.to_string()),
            branch: None,
            tool: "canary".to_string(),
            title: cluster.to_string(),
            quality_flags: String::new(),
        }
    }

    #[test]
    fn clusters_are_labeled_branch_delta_backport_gap_or_both() {
        let rows = vec![
            row("src/a.c:100", "base"),
            row("src/a.c:100", "head"),
            row("src/a.c:300", "base"),
            row("src/a.c:500", "head"),
        ];
        let base = revision_rows(&rows, "t1", "base");
        let head = revision_rows(&rows, "t1", "head");

        let entries = labeled_entries(&base, &head);

        let lead = |cluster: &str| {
            entries
                .iter()
                .find(|entry| entry.cluster_id == cluster)
                .unwrap()
                .lead
        };
        assert_eq!(lead("src/a.c:100"), FindingLead::Both);
        assert_eq!(lead("src/a.c:300"), FindingLead::BackportGap);
        assert_eq!(lead("src/a.c:500"), FindingLead::BranchDelta);
        assert_eq!(entries.len(), 3, "one entry per cluster, not per row");
    }
}

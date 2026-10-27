//! One bounded history read for status, spending and the operator browser.
use super::snapshot::{CampaignSnapshot, SnapshotReader};
use anyhow::{Context, Result};
use serde::Serialize;
use std::{collections::BTreeSet, fs, path::Path};

pub const HISTORY_ENTRY_LIMIT: usize = 1000;
pub const HISTORY_CAMPAIGN_LIMIT: usize = 100;
pub const HISTORY_METADATA_BYTES: usize = 32 * 1024 * 1024;
pub const HISTORY_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const HISTORY_RUN_BYTES: usize = 256 * 1024;
pub const HISTORY_JOB_LIMIT: usize = 1000;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignHistoryCoverage {
    pub directory_unreadable: bool,
    pub visited_entries: usize,
    pub inspected_bytes: usize,
    pub accounted_metadata_bytes: usize,
    pub unreadable_campaigns: usize,
    pub skipped_symlinks: usize,
    pub unreadable_run_metadata: usize,
    pub entry_limit_reached: bool,
    pub campaign_limit_reached: bool,
    pub byte_limit_reached: bool,
}

impl CampaignHistoryCoverage {
    pub fn complete(&self) -> bool {
        let omitted = [
            self.unreadable_campaigns,
            self.skipped_symlinks,
            self.unreadable_run_metadata,
        ]
        .iter()
        .any(|count| *count > 0);
        let limited = [
            self.directory_unreadable,
            self.entry_limit_reached,
            self.campaign_limit_reached,
            self.byte_limit_reached,
        ]
        .contains(&true);
        !(omitted || limited)
    }

    pub fn limitation_label(&self) -> Option<String> {
        if self.directory_unreadable {
            return Some("History unavailable: its directory could not be read. Refresh after correcting the path or access. Spending is unknown.".into());
        }
        let details = [
            self.limit_notes(),
            format!(
                "{} unreadable, {} symlink(s) skipped",
                self.unreadable_campaigns + self.unreadable_run_metadata,
                self.skipped_symlinks
            ),
        ]
        .into_iter()
        .filter(|note| !note.is_empty())
        .collect::<Vec<_>>()
        .join(". ");
        (!self.complete()).then(|| format!(
            "History partial: {details}. Spending may be incomplete. Open an exact ID with campaign <id>."
        ))
    }

    fn limit_notes(&self) -> String {
        [
            (
                self.entry_limit_reached,
                format!("directory limit of {HISTORY_ENTRY_LIMIT} entries reached"),
            ),
            (
                self.campaign_limit_reached,
                format!("limit of {HISTORY_CAMPAIGN_LIMIT} investigations reached"),
            ),
            (
                self.byte_limit_reached,
                format!(
                    "metadata limit of {} MiB reached",
                    HISTORY_METADATA_BYTES / (1024 * 1024)
                ),
            ),
        ]
        .into_iter()
        .filter_map(|(hit, note)| hit.then_some(note))
        .collect::<Vec<_>>()
        .join(". ")
    }

    pub fn json(&self) -> serde_json::Value {
        let mut value =
            serde_json::to_value(self).expect("History coverage contains serializable counters");
        value["schemaVersion"] = 1.into();
        value["complete"] = self.complete().into();
        value["limits"] = serde_json::json!({"entries":HISTORY_ENTRY_LIMIT,"campaigns":HISTORY_CAMPAIGN_LIMIT,"metadataBytes":HISTORY_METADATA_BYTES,"fileBytes":HISTORY_FILE_BYTES,"runMetadataBytes":HISTORY_RUN_BYTES,"jobsPerCampaign":HISTORY_JOB_LIMIT});
        value
    }
}

#[derive(Clone, Debug, Default)]
pub struct CampaignHistory {
    pub campaigns: Vec<CampaignSnapshot>,
    pub coverage: CampaignHistoryCoverage,
    pub requested_error: Option<String>,
    pub plan_digests: std::collections::BTreeMap<String, String>,
}

impl CampaignHistory {
    pub fn spend(&self) -> super::trend::WorkspaceCampaignSpend {
        super::trend::WorkspaceCampaignSpend {
            observed_usd: self
                .campaigns
                .iter()
                .map(|row| row.total_cost_usd)
                .sum::<f64>()
                + 0.0,
            provider_spend_unresolved: !self.coverage.complete()
                || self
                    .campaigns
                    .iter()
                    .any(|row| row.provider_spend_unresolved),
        }
    }
}

pub fn load_campaign_history(
    root: &Path,
    preferred: Option<&str>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Option<CampaignHistory>> {
    if cancelled() {
        return Ok(None);
    }
    let mut history = CampaignHistory::default();
    let mut reader = SnapshotReader::new(root, cancelled);
    let mut seen = BTreeSet::new();
    load_preferred(&mut history, &mut reader, preferred, &mut seen)?;
    let entries = match crate::bounded_file::read_dir_within(root, &super::campaigns_dir(root)) {
        Ok(entries) => Some(entries),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(entries) = entries {
        scan_entries(&mut history, &mut reader, entries, &mut seen, cancelled);
    }
    if cancelled() {
        return Ok(None);
    }
    history.coverage.inspected_bytes = reader.inspected_bytes;
    history.coverage.accounted_metadata_bytes = reader.accounted_bytes;
    history.coverage.byte_limit_reached = reader.byte_limit_reached;
    history.coverage.unreadable_run_metadata = reader.unreadable_run_metadata;
    history.plan_digests = reader.plan_digests;
    history
        .campaigns
        .sort_by(|a, b| a.campaign_id.cmp(&b.campaign_id));
    Ok(Some(history))
}

fn load_preferred(
    history: &mut CampaignHistory,
    reader: &mut SnapshotReader<'_>,
    id: Option<&str>,
    seen: &mut BTreeSet<String>,
) -> Result<()> {
    let Some(id) = id else {
        return Ok(());
    };
    super::validate_scan_batch_id(id)?;
    seen.insert(id.into());
    match reader.load(id, true) {
        Ok(snapshot) => history.campaigns.push(snapshot),
        Err(error) => {
            history.coverage.unreadable_campaigns += 1;
            history.requested_error = Some(format!("campaign {id:?} unavailable: {error:#}"));
        }
    }
    Ok(())
}

fn scan_entries(
    history: &mut CampaignHistory,
    reader: &mut SnapshotReader<'_>,
    entries: fs::ReadDir,
    seen: &mut BTreeSet<String>,
    cancelled: &dyn Fn() -> bool,
) {
    for entry in entries
        .take(HISTORY_ENTRY_LIMIT + 1)
        .take_while(|_| !cancelled())
    {
        history.coverage.visited_entries += 1;
        if history.coverage.visited_entries > HISTORY_ENTRY_LIMIT {
            history.coverage.entry_limit_reached = true;
            break;
        }
        visit_entry(history, reader, entry, seen);
        if history_limit_reached(history, reader) {
            break;
        }
    }
}

fn history_limit_reached(history: &CampaignHistory, reader: &SnapshotReader<'_>) -> bool {
    reader.byte_limit_reached || history.coverage.campaign_limit_reached
}

fn visit_entry(
    history: &mut CampaignHistory,
    reader: &mut SnapshotReader<'_>,
    entry: std::io::Result<fs::DirEntry>,
    seen: &mut BTreeSet<String>,
) {
    let result = entry
        .map_err(anyhow::Error::from)
        .and_then(|entry| read_entry(history, reader, entry, seen));
    if result.is_err() {
        history.coverage.unreadable_campaigns += 1;
    }
}

fn read_entry(
    history: &mut CampaignHistory,
    reader: &mut SnapshotReader<'_>,
    entry: fs::DirEntry,
    seen: &mut BTreeSet<String>,
) -> Result<()> {
    let Some(id) = candidate_id(entry, &mut history.coverage)? else {
        return Ok(());
    };
    if !seen.insert(id.clone()) {
        return Ok(());
    }
    if history.campaigns.len() == HISTORY_CAMPAIGN_LIMIT {
        history.coverage.campaign_limit_reached = true;
        return Ok(());
    }
    history.campaigns.push(reader.load(&id, false)?);
    Ok(())
}

fn candidate_id(
    entry: fs::DirEntry,
    coverage: &mut CampaignHistoryCoverage,
) -> Result<Option<String>> {
    let kind = entry.file_type()?;
    if kind.is_symlink() {
        coverage.skipped_symlinks += 1;
        return Ok(None);
    }
    if !kind.is_dir() {
        return Ok(None);
    }
    let id = entry
        .file_name()
        .to_str()
        .context("Campaign id is not UTF-8")?
        .to_owned();
    Ok(Some(id))
}

#[cfg(test)]
mod tests;

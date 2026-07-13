use super::super::{RunSummary, RunSummaryEntry, RunSummaryEntryState, RunSummaryIssue};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::Path;

pub(super) const READY_STATE: i64 = 0;
pub(super) const ISSUE_STATE: i64 = 1;
pub(super) const MAX_ISSUE_JSON_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RunHistoryIndexEntry {
    pub(crate) run_id: String,
    pub(crate) started_at_unix: Option<u64>,
    pub(crate) issue: Option<RunSummaryIssue>,
}

pub(in crate::run_artifacts) struct CurrentRunHistoryPrefix {
    pub(in crate::run_artifacts) entries: Vec<RunHistoryIndexEntry>,
    pub(in crate::run_artifacts) canonical_total: u64,
    pub(in crate::run_artifacts) generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunHistoryCursor {
    pub generation: u64,
    pub state_rank: u8,
    pub started_at_unix: u64,
    pub ready_run_id: String,
    pub issue_run_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunHistoryPageInfo {
    pub canonical_total: u64,
    pub retained_count: u64,
    pub retained_bytes: u64,
    pub retention_max_rows: usize,
    pub retention_max_bytes: u64,
    pub oldest_retained: Option<RunHistoryCursor>,
    pub truncated: bool,
    pub generation: u64,
    pub canonical_digest: String,
    pub table_digest: String,
}

#[derive(Debug, Clone)]
pub(in crate::run_artifacts) struct IndexedRunHistoryPage {
    pub(in crate::run_artifacts) entries: Vec<RunHistoryIndexEntry>,
    /// The complete retained ordering window. Page callers use this bounded
    /// witness to prove that an undisplayed retained run cannot outrank the
    /// requested rows after its canonical metadata changes. It cannot prove
    /// anything about evicted rows, so callers must fail closed when
    /// `info.truncated` is true.
    pub(in crate::run_artifacts) retained_entries: Vec<RunHistoryIndexEntry>,
    pub(in crate::run_artifacts) next_cursor: Option<RunHistoryCursor>,
    pub(in crate::run_artifacts) info: RunHistoryPageInfo,
}

impl RunHistoryCursor {
    pub(super) fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.generation > 0,
            "run-history cursor generation is invalid"
        );
        anyhow::ensure!(self.state_rank <= 1, "run-history cursor state is invalid");
        match self.state_rank {
            0 => anyhow::ensure!(
                safe_index_component(&self.ready_run_id) && self.issue_run_id.is_empty(),
                "run-history ready cursor is malformed"
            ),
            1 => anyhow::ensure!(
                self.started_at_unix == 0
                    && self.ready_run_id.is_empty()
                    && safe_index_component(&self.issue_run_id),
                "run-history issue cursor is malformed"
            ),
            _ => unreachable!(),
        }
        Ok(())
    }

    pub(super) fn sqlite_values(&self) -> Result<(i64, i64, &str, &str)> {
        self.validate()?;
        Ok((
            i64::from(self.state_rank),
            i64::try_from(self.started_at_unix)
                .context("run-history cursor timestamp does not fit SQLite")?,
            &self.ready_run_id,
            &self.issue_run_id,
        ))
    }
}

impl RunHistoryIndexEntry {
    pub(super) fn ready(summary: &RunSummary) -> Self {
        Self {
            run_id: summary.run_id.clone(),
            started_at_unix: Some(summary.started_at_unix),
            issue: None,
        }
    }

    pub(super) fn from_summary_entry(entry: &RunSummaryEntry) -> Self {
        match &entry.state {
            RunSummaryEntryState::Ready(summary) => Self::ready(summary),
            RunSummaryEntryState::Issue(issue) => Self {
                run_id: entry.run_id.clone(),
                started_at_unix: None,
                issue: Some(bounded_issue(issue)),
            },
        }
    }

    pub(super) fn missing(run_id: &str) -> Self {
        Self {
            run_id: run_id.to_string(),
            started_at_unix: None,
            issue: Some(RunSummaryIssue::MissingMetadata),
        }
    }

    pub(super) fn cursor(&self, generation: u64) -> RunHistoryCursor {
        match self.started_at_unix {
            Some(started_at_unix) => RunHistoryCursor {
                generation,
                state_rank: READY_STATE as u8,
                started_at_unix,
                ready_run_id: self.run_id.clone(),
                issue_run_id: String::new(),
            },
            None => RunHistoryCursor {
                generation,
                state_rank: ISSUE_STATE as u8,
                started_at_unix: 0,
                ready_run_id: String::new(),
                issue_run_id: self.run_id.clone(),
            },
        }
    }

    pub(super) fn retained_bytes(&self) -> Result<u64> {
        let issue_bytes = self
            .issue
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()?
            .map_or(0, |value| value.len());
        let bytes = self
            .run_id
            .len()
            .checked_add(issue_bytes)
            .and_then(|value| value.checked_add(64))
            .context("run-history retained byte count overflowed")?;
        u64::try_from(bytes).context("run-history retained byte count does not fit u64")
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub(super) fn validate(&self) -> Result<()> {
        let ready = self.started_at_unix.is_some() && self.issue.is_none();
        let issue = self.started_at_unix.is_none() && self.issue.is_some();
        anyhow::ensure!(ready || issue, "run-history index entry state is invalid");
        anyhow::ensure!(
            safe_index_component(&self.run_id),
            "run-history index run id is unsafe"
        );
        Ok(())
    }
}

impl Ord for RunHistoryIndexEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        match (&self.started_at_unix, &other.started_at_unix) {
            (Some(left), Some(right)) => {
                right.cmp(left).then_with(|| other.run_id.cmp(&self.run_id))
            }
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => self.run_id.cmp(&other.run_id),
        }
    }
}

impl PartialOrd for RunHistoryIndexEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn bounded_issue(issue: &RunSummaryIssue) -> RunSummaryIssue {
    if serde_json::to_vec(issue).is_ok_and(|value| value.len() <= MAX_ISSUE_JSON_BYTES) {
        return issue.clone();
    }
    RunSummaryIssue::UnreadableMetadata(
        "run-history issue detail exceeded the index limit".to_string(),
    )
}

pub(super) fn safe_index_component(run_id: &str) -> bool {
    let mut components = Path::new(run_id).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
        && run_id.len() <= 255
}

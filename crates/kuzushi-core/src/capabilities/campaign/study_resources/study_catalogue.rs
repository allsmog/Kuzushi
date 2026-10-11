//! Bounded, cancellable study choices. No source walk or model requests.
use super::*;
use serde_json::json;
use std::fs;

pub const STUDY_HISTORY_ENTRY_LIMIT: usize = 1000;
pub const STUDY_HISTORY_CHOICE_LIMIT: usize = 100;
const FILE_BYTES: usize = 1024 * 1024;
const HISTORY_BYTES: usize = 32 * FILE_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StudyUsageChoice {
    pub campaign_id: String,
    pub kind: String,
    pub planned_jobs: usize,
    pub completed_jobs: Option<usize>,
    pub created_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StudyUsageCatalogue {
    pub choices: Vec<StudyUsageChoice>,
    pub visited_entries: usize,
    pub inspected_bytes: usize,
    pub unreadable_entries: usize,
    pub skipped_symlinks: usize,
    pub entry_limit_reached: bool,
    pub byte_limit_reached: bool,
    pub choice_limit_reached: bool,
}

pub fn load_study_usage_catalogue(
    root: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<Option<StudyUsageCatalogue>> {
    if cancelled() {
        return Ok(None);
    }
    let path = super::super::campaigns_dir(root);
    let entries = match crate::bounded_file::read_dir_within(root, &path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Some(StudyUsageCatalogue::default()))
        }
        Err(error) => return Err(error.into()),
    };
    let mut reader = HistoryReader {
        root,
        result: StudyUsageCatalogue::default(),
    };
    if !scan_history_entries(&mut reader, entries, cancelled) || cancelled() {
        return Ok(None);
    }
    finalize(&mut reader.result);
    Ok(Some(reader.result))
}

fn scan_history_entries(
    reader: &mut HistoryReader<'_>,
    entries: fs::ReadDir,
    cancelled: &dyn Fn() -> bool,
) -> bool {
    for entry in entries.take(STUDY_HISTORY_ENTRY_LIMIT + 1) {
        if cancelled() {
            return false;
        }
        if !reader.visit(entry) {
            break;
        }
    }
    true
}

struct HistoryReader<'a> {
    root: &'a Path,
    result: StudyUsageCatalogue,
}

impl HistoryReader<'_> {
    fn visit(&mut self, entry: std::io::Result<fs::DirEntry>) -> bool {
        self.result.visited_entries += 1;
        if self.result.visited_entries > STUDY_HISTORY_ENTRY_LIMIT {
            self.result.entry_limit_reached = true;
            return false;
        }
        match entry.and_then(|entry| self.read_entry(entry).map_err(std::io::Error::other)) {
            Ok(Some(choice)) => self.result.choices.push(choice),
            Ok(None) => {}
            Err(_) => self.result.unreadable_entries += 1,
        }
        !self.result.byte_limit_reached
    }

    fn read_entry(&mut self, entry: fs::DirEntry) -> Result<Option<StudyUsageChoice>> {
        let metadata = entry.file_type()?;
        if metadata.is_symlink() {
            self.result.skipped_symlinks += 1;
            return Ok(None);
        }
        if !metadata.is_dir() {
            return Ok(None);
        }
        let id = entry
            .file_name()
            .to_str()
            .context("Study id is not UTF-8")?
            .to_owned();
        super::super::validate_scan_batch_id(&id)?;
        let plan = self.read_json(&entry.path().join("plan.json"))?;
        let Some(kind) = study_kind(&plan) else {
            return Ok(None);
        };
        require_study_header(&id, &plan)?;
        let completed_jobs = self.completed_jobs(&entry.path().join("queue.json"), &plan);
        Ok(Some(StudyUsageChoice {
            campaign_id: id,
            kind: kind.into(),
            planned_jobs: plan["jobs"].as_array().unwrap().len(),
            completed_jobs,
            created_at_ms: plan["createdAtMs"].as_u64(),
        }))
    }

    fn read_json(&mut self, path: &Path) -> Result<Value> {
        let remaining = HISTORY_BYTES.saturating_sub(self.result.inspected_bytes);
        self.require_available_bytes(path, remaining)?;
        if remaining == 0 {
            self.result.byte_limit_reached = true;
            anyhow::bail!("Study history metadata allowance exhausted");
        }
        let body =
            crate::bounded_file::read_utf8_text_within(self.root, path, remaining.min(FILE_BYTES))?;
        self.result.inspected_bytes += body.len();
        self.result.byte_limit_reached = self.result.inspected_bytes == HISTORY_BYTES;
        Ok(serde_json::from_str(&body)?)
    }

    fn require_available_bytes(&mut self, path: &Path, remaining: usize) -> Result<()> {
        let file = crate::bounded_file::open_regular_file_within(self.root, path)?;
        if remaining < FILE_BYTES && file.metadata()?.len() > remaining as u64 {
            self.result.byte_limit_reached = true;
            anyhow::bail!("Study history metadata allowance exhausted");
        }
        Ok(())
    }

    fn completed_jobs(&mut self, path: &Path, plan: &Value) -> Option<usize> {
        let queue = match self.read_json(path) {
            Ok(queue) => queue,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Some(0)
            }
            Err(_) => {
                self.result.unreadable_entries += 1;
                return None;
            }
        };
        let jobs = queue["jobs"].as_object()?;
        if jobs.len() > 100 {
            return None;
        }
        Some(
            plan["jobs"]
                .as_array()?
                .iter()
                .filter(|job| {
                    job["jobId"]
                        .as_str()
                        .and_then(|id| jobs.get(id))
                        .is_some_and(|state| state["state"] == "completed")
                })
                .count(),
        )
    }
}

fn study_kind(plan: &Value) -> Option<&str> {
    plan["kind"]
        .as_str()
        .filter(|kind| matches!(*kind, "scope-study" | "context-matrix"))
}

fn require_study_header(id: &str, plan: &Value) -> Result<()> {
    anyhow::ensure!(
        plan["schemaVersion"] == json!(1) && plan["campaignId"] == json!(id),
        "Study header differs from its directory"
    );
    let jobs = plan["jobs"].as_array().context("Study jobs missing")?;
    anyhow::ensure!(
        (1..=100).contains(&jobs.len()),
        "Study jobs exceed the supported workload"
    );
    Ok(())
}

fn finalize(catalogue: &mut StudyUsageCatalogue) {
    catalogue.choices.sort_by(|a, b| {
        b.created_at_ms
            .cmp(&a.created_at_ms)
            .then(a.campaign_id.cmp(&b.campaign_id))
    });
    catalogue.choice_limit_reached = catalogue.choices.len() > STUDY_HISTORY_CHOICE_LIMIT;
    catalogue.choices.truncate(STUDY_HISTORY_CHOICE_LIMIT);
}

#[cfg(test)]
mod tests;

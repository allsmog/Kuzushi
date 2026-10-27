//! Bounded metadata reads shared by direct snapshots and history pages.
use super::*;
use std::collections::BTreeMap;
use std::io;

use super::super::history::{
    HISTORY_FILE_BYTES as FILE_BYTES, HISTORY_JOB_LIMIT as JOB_LIMIT,
    HISTORY_METADATA_BYTES as HISTORY_BYTES, HISTORY_RUN_BYTES as RUN_BYTES,
};

pub(in crate::capabilities::campaign) struct SnapshotReader<'a> {
    root: &'a Path,
    cancelled: &'a dyn Fn() -> bool,
    pub inspected_bytes: usize,
    pub accounted_bytes: usize,
    pub byte_limit_reached: bool,
    pub unreadable_run_metadata: usize,
    pub plan_digests: BTreeMap<String, String>,
    runs: BTreeMap<String, Option<Value>>,
}

impl<'a> SnapshotReader<'a> {
    pub(in crate::capabilities::campaign) fn new(
        root: &'a Path,
        cancelled: &'a dyn Fn() -> bool,
    ) -> Self {
        Self {
            root,
            cancelled,
            inspected_bytes: 0,
            accounted_bytes: 0,
            byte_limit_reached: false,
            unreadable_run_metadata: 0,
            plan_digests: BTreeMap::new(),
            runs: BTreeMap::new(),
        }
    }

    pub(in crate::capabilities::campaign) fn load(
        &mut self,
        id: &str,
        include_runs: bool,
    ) -> Result<CampaignSnapshot> {
        super::super::validate_scan_batch_id(id)?;
        let plan = self
            .read_json(&campaign_plan_path(self.root, id), FILE_BYTES)
            .with_context(|| format!("campaign {id:?} has no readable plan"))?;
        require_document_id(&plan, id)?;
        let jobs = plan["jobs"]
            .as_array()
            .context("Campaign plan has no job list")?;
        anyhow::ensure!(
            jobs.len() <= JOB_LIMIT,
            "Campaign snapshot exceeds {JOB_LIMIT} jobs"
        );
        let queue = self.read_queue(id)?;
        let cancelled = self.cancelled;
        let snapshot = fold_documents(
            id,
            &plan,
            &queue,
            &mut |run| include_runs.then(|| self.run(run)).flatten(),
            cancelled,
        )?;
        let digest = super::super::batch::equivalence::digest_serializable(&plan)?;
        self.plan_digests.insert(id.into(), digest);
        Ok(snapshot)
    }

    fn read_queue(&mut self, id: &str) -> Result<Value> {
        let queue = match self.read_json(&campaign_queue_path(self.root, id), FILE_BYTES) {
            Ok(value) => value,
            Err(error) if missing(&error) => return Ok(Value::Null),
            Err(error) => {
                return Err(error).with_context(|| format!("campaign {id:?} has no readable queue"))
            }
        };
        require_document_id(&queue, id)?;
        anyhow::ensure!(
            queue["jobs"].is_object(),
            "Campaign queue has no readable job map"
        );
        Ok(queue)
    }

    pub(in crate::capabilities::campaign) fn run(&mut self, id: &str) -> Option<Value> {
        if let Some(run) = self.runs.get(id) {
            return run.clone();
        }
        let result = self.read_run(id);
        let value = match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.unreadable_run_metadata += usize::from(!missing(&error));
                None
            }
        };
        self.runs.insert(id.into(), value.clone());
        value
    }

    fn read_run(&mut self, id: &str) -> Result<Value> {
        let path = crate::run_artifacts::checked_run_artifact_path(self.root, id, "run.json")?;
        let value = self.read_json(&path, RUN_BYTES)?;
        if legacy_count_only(&value) {
            require_legacy_identity(&value, id)?;
        } else {
            crate::run_artifacts::decode_run_summary_value(value.clone(), id)?;
        }
        Ok(value)
    }

    fn read_json(&mut self, path: &Path, per_file_limit: usize) -> Result<Value> {
        anyhow::ensure!(
            !(self.cancelled)(),
            "Investigation history loading was canceled"
        );
        let remaining = HISTORY_BYTES.saturating_sub(self.accounted_bytes);
        self.check_remaining(0, per_file_limit, remaining)?;
        let file = crate::bounded_file::open_regular_file_within(self.root, path)?;
        self.check_remaining(file.metadata()?.len(), per_file_limit, remaining)?;
        let limit = remaining.min(per_file_limit);
        self.accounted_bytes += limit;
        let read = crate::bounded_file::read_open_regular_bytes(path, file, limit);
        let bytes = self.complete_read(limit, read)?;
        anyhow::ensure!(
            !(self.cancelled)(),
            "Investigation history loading was canceled"
        );
        serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is malformed JSON", path.display()))
    }

    fn complete_read(&mut self, reserved: usize, read: io::Result<Vec<u8>>) -> Result<Vec<u8>> {
        let bytes = read?;
        self.inspected_bytes += bytes.len();
        self.accounted_bytes -= reserved.saturating_sub(bytes.len());
        Ok(bytes)
    }

    fn check_remaining(
        &mut self,
        size: u64,
        per_file_limit: usize,
        remaining: usize,
    ) -> Result<()> {
        if size > per_file_limit as u64 {
            anyhow::bail!("Campaign metadata exceeds {per_file_limit} bytes per file");
        }
        if size > remaining as u64 || remaining == 0 {
            self.byte_limit_reached = true;
            anyhow::bail!("Investigation history exceeds {HISTORY_BYTES} metadata bytes");
        }
        Ok(())
    }
}

fn legacy_count_only(value: &Value) -> bool {
    let Some(fields) = value.as_object() else {
        return false;
    };
    let count_present = value["findings"].as_u64().is_some();
    count_present
        && fields
            .keys()
            .all(|key| matches!(key.as_str(), "runId" | "status" | "findings"))
}

fn require_legacy_identity(value: &Value, id: &str) -> Result<()> {
    if let Some(recorded) = value.get("runId") {
        anyhow::ensure!(
            recorded.as_str() == Some(id),
            "Legacy finding count belongs to another run"
        );
    }
    Ok(())
}

fn missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
}

fn require_document_id(value: &Value, id: &str) -> Result<()> {
    if let Some(recorded) = value.get("campaignId") {
        anyhow::ensure!(
            recorded.as_str() == Some(id),
            "Campaign document belongs to another investigation"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertain_failed_reads_keep_their_reserved_metadata_allowance() {
        let root = tempfile::tempdir().unwrap();
        let mut reader = SnapshotReader::new(root.path(), &|| false);
        reader.accounted_bytes = FILE_BYTES;
        let result = reader.complete_read(
            FILE_BYTES,
            Err(io::Error::other("Owned simulated interrupted read")),
        );
        assert!(result.is_err());
        assert_eq!(reader.accounted_bytes, FILE_BYTES);
        assert_eq!(reader.inspected_bytes, 0);
        reader.accounted_bytes += RUN_BYTES;
        reader.complete_read(RUN_BYTES, Ok(vec![b'a'; 8])).unwrap();
        assert_eq!(reader.accounted_bytes, FILE_BYTES + 8);
        assert_eq!(reader.inspected_bytes, 8);
    }
}

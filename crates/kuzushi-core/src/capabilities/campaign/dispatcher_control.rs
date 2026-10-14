//! Cooperative stop requests bound to one exclusive dispatcher session.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_CONTROL_BYTES: u64 = 4096;
const OWNER_FILE: &str = "dispatcher-control.json";
const STOP_FILE: &str = "dispatcher-stop.json";

/// Read a bounded failure explanation after an owned dispatcher exits.
pub fn read_campaign_dispatcher_error(root: &Path, campaign_id: &str) -> Result<Option<String>> {
    super::validate_scan_batch_id(campaign_id)?;
    let path = super::campaign_dir(root, campaign_id).join("logs/dispatcher.log");
    let text = crate::bounded_file::read_utf8_text_within(root, &path, 2 * 1024 * 1024)?;
    Ok(text
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("Error: "))
        .map(|cause| {
            crate::run_lifecycle::SafeText::preview_line(cause)
                .as_str()
                .to_string()
        }))
}

#[derive(Clone, Debug)]
pub struct CampaignDispatcherControl {
    directory: PathBuf,
    owner: DispatcherOwner,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DispatcherOwner {
    schema_version: u32,
    session_id: String,
    campaign_id: String,
    pid: u32,
}

impl CampaignDispatcherControl {
    pub(super) fn publish(root: &Path, campaign_id: &str) -> Result<Self> {
        super::validate_scan_batch_id(campaign_id)?;
        let control = Self {
            directory: super::campaign_dir(root, campaign_id),
            owner: DispatcherOwner {
                schema_version: 1,
                session_id: uuid::Uuid::new_v4().to_string(),
                campaign_id: campaign_id.into(),
                pid: std::process::id(),
            },
        };
        write_control(&control.directory.join(OWNER_FILE), &control.owner)?;
        Ok(control)
    }

    pub fn stop_requested(&self) -> Result<bool> {
        let path = self.directory.join(STOP_FILE);
        if !path.try_exists()? {
            return Ok(false);
        }
        let request = read_control(&path)?;
        Ok(request == self.owner)
    }
}

/// The caller must hold the live child handle for `pid`. The request never
/// signals a process and a later dispatcher ignores its previous session.
pub fn request_campaign_dispatcher_stop(root: &Path, campaign_id: &str, pid: u32) -> Result<()> {
    super::validate_scan_batch_id(campaign_id)?;
    let directory = super::campaign_dir(root, campaign_id);
    let owner = read_control(&directory.join(OWNER_FILE))?;
    anyhow::ensure!(
        owner.campaign_id == campaign_id && owner.pid == pid,
        "dispatcher ownership changed; refresh before requesting Stop"
    );
    write_control(&directory.join(STOP_FILE), &owner)
}

fn read_control(path: &Path) -> Result<DispatcherOwner> {
    anyhow::ensure!(
        std::fs::symlink_metadata(path)?.file_type().is_file(),
        "dispatcher control must be an owned regular file"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_CONTROL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_CONTROL_BYTES,
        "dispatcher control exceeds its size limit"
    );
    let owner: DispatcherOwner =
        serde_json::from_slice(&bytes).context("dispatcher control is malformed")?;
    anyhow::ensure!(
        owner.schema_version == 1 && owner.pid > 0,
        "unsupported dispatcher control record"
    );
    uuid::Uuid::parse_str(&owner.session_id).context("dispatcher session identity is invalid")?;
    super::validate_scan_batch_id(&owner.campaign_id)?;
    Ok(owner)
}

fn write_control(path: &Path, owner: &DispatcherOwner) -> Result<()> {
    std::fs::create_dir_all(path.parent().context("dispatcher control has no parent")?)?;
    crate::fs_atomic::write_atomic(path, &serde_json::to_string(owner)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod error_reader;

    #[test]
    fn stop_is_idempotent_and_a_previous_session_cannot_stop_a_new_dispatcher() {
        let root = tempfile::tempdir().unwrap();
        let first = CampaignDispatcherControl::publish(root.path(), "owned").unwrap();
        assert!(!first.stop_requested().unwrap());
        request_campaign_dispatcher_stop(root.path(), "owned", std::process::id()).unwrap();
        assert!(first.stop_requested().unwrap());
        request_campaign_dispatcher_stop(root.path(), "owned", std::process::id()).unwrap();
        let next = CampaignDispatcherControl::publish(root.path(), "owned").unwrap();
        assert!(!next.stop_requested().unwrap());
        assert!(first.stop_requested().unwrap());
    }

    #[test]
    fn wrong_pid_and_invalid_control_do_not_create_a_stop_request() {
        let root = tempfile::tempdir().unwrap();
        let control = CampaignDispatcherControl::publish(root.path(), "owned").unwrap();
        assert!(request_campaign_dispatcher_stop(root.path(), "owned", 0).is_err());
        assert!(!control.stop_requested().unwrap());
        std::fs::write(control.directory.join(OWNER_FILE), "{}").unwrap();
        assert!(
            request_campaign_dispatcher_stop(root.path(), "owned", std::process::id()).is_err()
        );
        assert!(!control.stop_requested().unwrap());
    }

    #[test]
    fn malformed_or_oversized_requests_are_errors_and_paths_stay_contained() {
        let root = tempfile::tempdir().unwrap();
        let control = CampaignDispatcherControl::publish(root.path(), "owned").unwrap();
        let path = control.directory.join(STOP_FILE);
        std::fs::write(&path, "{}").unwrap();
        assert!(control.stop_requested().is_err());
        std::fs::write(path, vec![b' '; MAX_CONTROL_BYTES as usize + 1]).unwrap();
        assert!(control.stop_requested().is_err());
        assert!(CampaignDispatcherControl::publish(root.path(), "../outside").is_err());
    }
}

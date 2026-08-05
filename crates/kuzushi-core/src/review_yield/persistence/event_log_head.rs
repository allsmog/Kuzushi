use anyhow::{Context, Result};

use crate::event_log::EventLog;
use crate::workspace::WorkspaceTarget;

/// Where the target's event log stood when the dataset was read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventLogHead {
    pub seq: u64,
    pub hash: Option<String>,
}

/// Reads the head of the target's event log. An empty log reports sequence 0
/// with no hash rather than a fabricated one.
pub fn read_event_log_head(workspace: &WorkspaceTarget) -> Result<EventLogHead> {
    let log = EventLog::open(workspace.event_log_dir())
        .context("could not open the target event log")?;
    let seq = log.head_seq()?;
    let hash = log
        .read_all()
        .context("could not read the target event log")?
        .last()
        .map(|event| event.event_hash.as_str().to_string());
    Ok(EventLogHead { seq, hash })
}

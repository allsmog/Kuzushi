//! Bounded startup classification; operational receipts do not establish an investigation.
use crate::modules::{ModuleRegistry, ToolPhase};
use crate::run_artifacts::{
    checked_runs_root, list_current_run_summary_prefix, RunSummaryEntryState,
};
use anyhow::Result;
use std::path::Path;

const STARTUP_HISTORY_LIMIT: usize = 32;

impl ModuleRegistry {
    /// Inspect a current bounded history prefix without rebuilding or repairing
    /// it. Unavailable, incomplete or unclassified history preserves resume
    /// behavior; it never establishes phase completion or repository coverage.
    pub fn investigation_history_requires_resume(&self, target: &Path) -> Result<bool> {
        if !checked_runs_root(target)?.try_exists()? {
            return Ok(false);
        }
        let Some(history) = list_current_run_summary_prefix(target, STARTUP_HISTORY_LIMIT)? else {
            return Ok(true);
        };
        if history.canonical_total > history.entries.len() as u64 {
            return Ok(true);
        }
        Ok(history
            .entries
            .iter()
            .any(|entry| self.entry_requires_resume(&entry.state)))
    }

    fn entry_requires_resume(&self, state: &RunSummaryEntryState) -> bool {
        let RunSummaryEntryState::Ready(summary) = state else {
            return true;
        };
        summary
            .tool
            .as_deref()
            .and_then(|tool| self.resolve_tool(tool))
            .is_none_or(|descriptor| {
                descriptor.phase_result && descriptor.phase != ToolPhase::Operate
            })
    }
}

#[cfg(test)]
mod tests;

use super::*;
use std::path::PathBuf;

/// Cap on retained command-history entries, in memory and on disk.
pub(crate) const COMMAND_HISTORY_CAP: usize = 200;

impl ShellApp {
    /// Resolve the per-workspace history file. History is scoped to a target so
    /// each project keeps its own command trail — and so a target-less session
    /// never writes to the operator's global home behind their back. Returns
    /// `None` when no workspace is selected (history stays in-memory only).
    pub(crate) fn history_file_path(&self) -> Option<PathBuf> {
        let paths = kuzushi_core::ConfigPaths::from_target(self.target()).ok()?;
        paths.project_history_path()
    }

    /// Load persisted history at startup. Missing file is a silent cold start;
    /// a read error is surfaced to the transcript and leaves history empty.
    pub(crate) fn load_persisted_history(&mut self) {
        let Some(path) = self.history_file_path() else {
            return;
        };
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let mut entries: Vec<String> = contents
                    .lines()
                    .map(str::trim_end)
                    .filter(|line| !line.is_empty())
                    .map(str::to_string)
                    .collect();
                let overflow = entries.len().saturating_sub(COMMAND_HISTORY_CAP);
                entries.drain(0..overflow);
                self.editor_mut().replace_command_history(entries);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => self.log("history", format!("could not load history: {error}")),
        }
    }

    /// Persist the (capped) history. Failures are logged, never fatal — an
    /// unwritable `.kuzushi` dir must not break the session.
    pub(crate) fn persist_command_history(&mut self) {
        let Some(path) = self.history_file_path() else {
            return;
        };
        if let Err(error) = write_history_file(&path, self.command_history()) {
            self.log("history", format!("could not persist history: {error}"));
        }
    }
}

fn write_history_file(path: &PathBuf, entries: &[String]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = entries.join("\n");
    std::fs::write(path, body)
}

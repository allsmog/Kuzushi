use super::*;
use std::path::{Path, PathBuf};

/// Cap on retained command-history entries, in memory and on disk.
pub(crate) const COMMAND_HISTORY_CAP: usize = 200;
const MAX_COMMAND_HISTORY_BYTES: usize = 1024 * 1024;

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
        let Some(root) = self.target_owned() else {
            return;
        };
        let path = kuzushi_core::workspace::workspace_history_path(&root);
        match kuzushi_core::workspace::read_optional_workspace_text(
            &root,
            &path,
            MAX_COMMAND_HISTORY_BYTES,
        ) {
            Ok(Some(contents)) => {
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
            Ok(None) => {}
            Err(error) => self.log("history", format!("could not load history: {error}")),
        }
    }

    /// Persist the (capped) history. Failures are logged, never fatal — an
    /// unwritable `.kuzushi` dir must not break the session.
    pub(crate) fn persist_command_history(&mut self) {
        let Some(root) = self.target_owned() else {
            return;
        };
        if let Err(error) = write_history_file(&root, self.command_history()) {
            self.log("history", format!("could not persist history: {error}"));
        }
    }
}

fn write_history_file(root: &Path, entries: &[String]) -> anyhow::Result<()> {
    let body = entries.join("\n");
    let history_path = kuzushi_core::workspace::workspace_history_path(root);
    let relative = history_path
        .strip_prefix(root)
        .map_err(|_| anyhow::anyhow!("workspace history path escaped the active target"))?;
    kuzushi_core::workspace::write_workspace_state_file(root, relative, body.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn history_writer_rejects_a_symlinked_artifact() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().expect("workspace");
        let mut outside = tempfile::NamedTempFile::new().expect("outside");
        std::io::Write::write_all(&mut outside, b"outside").expect("seed outside");
        let state_dir = kuzushi_core::workspace::workspace_state_dir(workspace.path());
        std::fs::create_dir_all(&state_dir).expect("state dir");
        symlink(
            outside.path(),
            kuzushi_core::workspace::workspace_history_path(workspace.path()),
        )
        .expect("symlink artifact");

        let error = write_history_file(workspace.path(), &["findings".to_string()])
            .expect_err("symlink must be rejected");

        assert!(error.to_string().contains("symlink"));
        assert_eq!(std::fs::read_to_string(outside.path()).unwrap(), "outside");
    }

    #[cfg(unix)]
    #[test]
    fn history_reader_rejects_an_outside_symlink_without_loading_content() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().expect("workspace");
        let outside = tempfile::NamedTempFile::new().expect("outside");
        std::fs::write(outside.path(), "OUTSIDE_HISTORY_TOKEN").unwrap();
        let state_dir = kuzushi_core::workspace::workspace_state_dir(workspace.path());
        std::fs::create_dir_all(&state_dir).unwrap();
        symlink(
            outside.path(),
            kuzushi_core::workspace::workspace_history_path(workspace.path()),
        )
        .unwrap();
        let target = kuzushi_core::WorkspaceTarget::new(workspace.path()).unwrap();
        let config = kuzushi_core::V2Config::default();
        let mut app = ShellApp::new(config, Some(&target));

        app.load_persisted_history();

        assert!(app.command_history().is_empty());
        assert!(!app.log_lines().iter().any(|line| {
            line.prefix.contains("OUTSIDE_HISTORY_TOKEN")
                || line.body.contains("OUTSIDE_HISTORY_TOKEN")
        }));
    }
}

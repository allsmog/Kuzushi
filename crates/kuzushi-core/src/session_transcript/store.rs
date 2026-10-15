use super::model::*;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

mod conversations;
mod discovery;
mod reader;
mod secure_directory;

pub(super) use discovery::validate_session_id;
use discovery::{collect_session_files, filename_has_session_id, read_safe_session_file};
use reader::{parse_records, read_matches_target, summarize};
use secure_directory::ensure_secure_child;
pub(super) use secure_directory::reject_kuzushi_symlink_ancestors;
pub(super) use secure_directory::{ensure_secure_directory, validate_secure_directory};

#[derive(Debug, Clone)]
pub struct SessionTranscriptStore {
    root: PathBuf,
}

impl SessionTranscriptStore {
    pub fn for_home(home: impl AsRef<Path>) -> Self {
        Self::from_root(default_sessions_root(home))
    }

    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn start(&self, metadata: SessionMetadata) -> Result<super::SessionRecorder> {
        let session_id = Uuid::new_v4().to_string();
        let directory = self.daily_directory()?;
        let (_, _, _, timestamp) = super::time::date_path_components();
        let path = directory.join(format!("session-{timestamp}-{session_id}.jsonl"));
        super::SessionRecorder::start(path, session_id, metadata)
    }

    pub fn list(&self, options: &SessionListOptions) -> Result<Vec<SessionSummary>> {
        let mut summaries = self
            .session_files()?
            .into_iter()
            .filter_map(|path| self.read_path(path).ok())
            .filter(|read| read_matches_target(read, options.target.as_deref()))
            .map(|result| result.summary)
            .collect::<Vec<_>>();
        summaries.sort_by(|left, right| right.started_at.cmp(&left.started_at));
        Ok(summaries)
    }

    /// Read one transcript by path. The live shell already knows its own
    /// recorder path, so it reads back without rescanning the whole store.
    pub fn read_file(path: impl Into<PathBuf>) -> Result<SessionReadResult> {
        let path = path.into();
        let raw_jsonl = read_safe_session_file(&path)?;
        let (records, warnings) = parse_records(&raw_jsonl);
        let summary = summarize(&path, &records, warnings.len())?;
        Ok(SessionReadResult {
            path,
            raw_jsonl,
            summary,
            records,
            warnings,
        })
    }

    pub fn read(&self, session_id: &str) -> Result<SessionReadResult> {
        validate_session_id(session_id)?;
        let path = self
            .session_files()?
            .into_iter()
            .find(|path| filename_has_session_id(path, session_id))
            .with_context(|| format!("session {session_id} was not found"))?;
        self.read_path(path)
    }

    pub fn prune(&self, options: &SessionPruneOptions) -> Result<SessionPruneReport> {
        anyhow::ensure!(
            options.older_than_days > 0,
            "older_than_days must be greater than zero"
        );
        let cutoff = prune_cutoff(options.older_than_days);
        let files = self.session_files()?;
        let mut report = empty_prune_report(options.dry_run);
        for path in files {
            report.examined += 1;
            self.prune_file(path, cutoff, options, &mut report);
        }
        Ok(report)
    }

    fn daily_directory(&self) -> Result<PathBuf> {
        ensure_secure_directory(&self.root)?;
        let (year, month, day, _) = super::time::date_path_components();
        let year = ensure_secure_child(&self.root, &year)?;
        let month = ensure_secure_child(&year, &month)?;
        ensure_secure_child(&month, &day)
    }

    fn session_files(&self) -> Result<Vec<PathBuf>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        validate_secure_directory(&self.root)?;
        collect_session_files(&self.root, 4)
    }

    fn read_path(&self, path: PathBuf) -> Result<SessionReadResult> {
        Self::read_file(path)
    }

    fn prune_file(
        &self,
        path: PathBuf,
        cutoff: SystemTime,
        options: &SessionPruneOptions,
        report: &mut SessionPruneReport,
    ) {
        if !is_older_than(&path, cutoff) {
            return;
        }
        let read = match self.read_path(path.clone()) {
            Ok(read) => read,
            Err(error) => {
                report.errors.push(format!("{}: {error}", path.display()));
                return prune_unreadable_file(path, options, report);
            }
        };
        if read.summary.status == SessionStatus::Running {
            report.skipped_live.push(read.summary.session_id);
            return;
        }
        if options.dry_run || fs::remove_file(&path).is_ok() {
            report.removed.push(path);
        } else {
            report
                .errors
                .push(format!("could not remove {}", path.display()));
        }
    }
}

pub fn default_sessions_root(home: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_dir(home).join("sessions")
}

pub fn render_session_markdown(read: &SessionReadResult) -> String {
    let summary = &read.summary;
    let mut output = format!(
        "# Kuzushi session {}\n\n- Started: {}\n- Status: {:?}\n- Shell mode: {}\n",
        summary.session_id, summary.started_at, summary.status, summary.shell_mode
    );
    if let Some(target) = summary.current_target.as_deref() {
        output.push_str(&format!("- Target: `{}`\n", target.display()));
    }
    output.push_str("\n## Timeline\n\n");
    for record in &read.records {
        let payload = serde_json::to_string(&record.payload).unwrap_or_else(|_| "{}".to_string());
        output.push_str(&format!(
            "- `{}` **{}** `{payload}`\n",
            record.timestamp, record.event_type
        ));
    }
    output
}

fn prune_cutoff(days: u64) -> SystemTime {
    let seconds = days.saturating_mul(86_400);
    SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(seconds))
        .unwrap_or(UNIX_EPOCH)
}

fn is_older_than(path: &Path, cutoff: SystemTime) -> bool {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .is_ok_and(|modified| modified < cutoff)
}

fn empty_prune_report(dry_run: bool) -> SessionPruneReport {
    SessionPruneReport {
        examined: 0,
        removed: Vec::new(),
        skipped_live: Vec::new(),
        errors: Vec::new(),
        dry_run,
    }
}

fn prune_unreadable_file(
    path: PathBuf,
    options: &SessionPruneOptions,
    report: &mut SessionPruneReport,
) {
    let safe = fs::symlink_metadata(&path)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink());
    if !safe {
        return;
    }
    if options.dry_run || fs::remove_file(&path).is_ok() {
        report.removed.push(path);
    } else {
        report
            .errors
            .push(format!("could not remove {}", path.display()));
    }
}

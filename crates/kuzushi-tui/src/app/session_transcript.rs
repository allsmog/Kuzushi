use super::*;
use anyhow::{Context, Result};
use kuzushi_core::session_transcript::{
    default_sessions_root, SessionEvent, SessionGitMetadata, SessionMetadata, SessionPruneOptions,
    SessionRecorder, SessionTranscriptStore,
};

pub(crate) fn start_session_transcript(
    config: &V2Config,
    target: Option<&WorkspaceTarget>,
    launch: &ShellLaunchContext,
    shell_mode: &str,
) -> Result<SessionRecorder> {
    let home = kuzushi_core::ConfigPaths::from_target(None)?.home_dir;
    let root = default_sessions_root(home);
    let store = SessionTranscriptStore::from_root(root);
    let prune_warning = prune_expired_sessions(&store, config);
    let metadata = shell_session_metadata(target, launch, shell_mode)?;
    let recorder = store.start(metadata)?;
    if let Some(message) = prune_warning {
        let _ = recorder.record(SessionEvent::SessionWarning { message });
    }
    Ok(recorder)
}

fn prune_expired_sessions(store: &SessionTranscriptStore, config: &V2Config) -> Option<String> {
    let options = SessionPruneOptions {
        older_than_days: config.operator.session_retention_days,
        dry_run: false,
    };
    store
        .prune(&options)
        .err()
        .map(|error| format!("automatic session cleanup failed: {error}"))
}

fn shell_session_metadata(
    target: Option<&WorkspaceTarget>,
    launch: &ShellLaunchContext,
    shell_mode: &str,
) -> Result<SessionMetadata> {
    let cwd = std::env::current_dir().context("Could not resolve shell cwd")?;
    let mut metadata = SessionMetadata::new(shell_mode, cwd);
    metadata.argv = launch.argv.clone();
    metadata.kuzushi_version = crate::build_version();
    metadata.build = Some(crate::build_summary());
    metadata.initial_target = target.map(|target| target.root().to_path_buf());
    metadata.target_source = Some(launch.target_source.label().to_string());
    let git_root = target.map(WorkspaceTarget::root).unwrap_or(&metadata.cwd);
    metadata.git = session_git_metadata(git_root);
    Ok(metadata)
}

fn session_git_metadata(path: &std::path::Path) -> Option<SessionGitMetadata> {
    let git = kuzushi_core::workspace::target_git_metadata(path)?;
    Some(SessionGitMetadata {
        branch: git.branch,
        commit: Some(git.sha),
        dirty: Some(git.dirty),
        remote: None,
    })
}

pub(crate) struct ShellSessionTranscript {
    recorder: SessionRecorder,
    surfaced_error: Option<String>,
}

impl std::fmt::Debug for ShellSessionTranscript {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ShellSessionTranscript")
            .field("session_id", &self.recorder.session_id())
            .field("path", &self.recorder.path())
            .field("surfaced_error", &self.surfaced_error)
            .finish()
    }
}

impl ShellSessionTranscript {
    pub(crate) fn new(recorder: SessionRecorder) -> Self {
        Self {
            recorder,
            surfaced_error: None,
        }
    }

    pub(crate) fn record(&self, event: SessionEvent) -> Result<()> {
        let requires_flush = event.requires_flush_barrier();
        self.recorder.record(event)?;
        if requires_flush {
            self.recorder.flush()?;
        }
        Ok(())
    }

    pub(crate) fn flush(&self) -> Result<()> {
        self.recorder.flush()
    }

    pub(crate) fn current_error(&self) -> Option<String> {
        self.recorder.status().last_error
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        self.recorder.path()
    }

    pub(crate) fn status_line(&self) -> String {
        let status = self.recorder.status();
        let error = status
            .last_error
            .as_deref()
            .map(|error| format!(" warning={error}"))
            .unwrap_or_default();
        format!(
            "id={} path={} health={:?} flushed={} pending={}{}",
            self.recorder.session_id(),
            self.recorder.path().display(),
            status.health,
            status.last_flushed_sequence,
            status.pending_records,
            error,
        )
    }

    pub(crate) fn take_new_error(&mut self, error: String) -> Option<String> {
        if self.surfaced_error.as_deref() == Some(error.as_str()) {
            return None;
        }
        self.surfaced_error = Some(error.clone());
        Some(error)
    }

    pub(crate) fn mark_healthy(&mut self) {
        self.surfaced_error = None;
    }

    pub(crate) fn shutdown(&self, reason: &str) -> Result<()> {
        self.recorder.shutdown(reason)
    }
}

impl ShellApp {
    pub(crate) fn attach_session_transcript(&mut self, recorder: SessionRecorder) {
        self.session
            .attach_transcript(ShellSessionTranscript::new(recorder));
    }

    pub(crate) fn record_session_event(&mut self, event: SessionEvent) {
        let result = self
            .session
            .transcript()
            .map(|transcript| transcript.record(event));
        self.apply_session_transcript_result(result);
    }

    pub(crate) fn flush_session_transcript(&mut self) {
        let result = self.session.transcript().map(ShellSessionTranscript::flush);
        self.apply_session_transcript_result(result);
    }

    fn apply_session_transcript_result(&mut self, result: Option<Result<()>>) {
        let error = result
            .and_then(Result::err)
            .map(|error| error.to_string())
            .or_else(|| {
                self.session
                    .transcript()
                    .and_then(ShellSessionTranscript::current_error)
            });
        if let Some(error) = error {
            self.surface_session_transcript_error(error);
        } else if let Some(transcript) = self.session.transcript_mut() {
            transcript.mark_healthy();
        }
    }

    pub(crate) fn show_session_transcript_status(&mut self) {
        let status = self
            .session
            .transcript()
            .map(ShellSessionTranscript::status_line)
            .or_else(|| {
                self.session
                    .transcript_start_warning()
                    .map(|warning| format!("recording unavailable: {warning}"))
            })
            .unwrap_or_else(|| "durable transcript disabled for this shell".to_string());
        self.log("session", status);
    }

    pub(crate) fn surface_session_start_warning(&mut self, warning: String) {
        self.session.set_transcript_start_warning(warning.clone());
        self.push_session_warning(warning);
    }

    pub(crate) fn session_persistence_is_degraded(&self) -> bool {
        self.session.transcript_start_warning().is_some()
            || self
                .session
                .transcript()
                .is_some_and(|transcript| transcript.current_error().is_some())
    }

    pub(crate) fn finish_session_transcript(&mut self, reason: &str) {
        let Some(transcript) = self.session.take_transcript() else {
            return;
        };
        if let Err(error) = transcript.shutdown(reason) {
            self.push_session_warning(format!(
                "durable transcript could not finish cleanly: {error}; pending records will be retried when possible"
            ));
        }
    }

    pub(crate) fn surface_session_transcript_error(&mut self, error: String) -> bool {
        let warning = self
            .session
            .transcript_mut()
            .and_then(|transcript| transcript.take_new_error(error));
        let Some(warning) = warning else {
            return false;
        };
        self.push_session_warning(format!(
            "durable transcript is degraded: {warning}; Kuzushi will continue and retry"
        ));
        true
    }

    fn push_session_warning(&mut self, message: String) {
        self.domain.push_log("session", message.clone());
        self.advisory_mut().notice = Some(Notice {
            source: "session".to_string(),
            message,
            severity: NoticeSeverity::Warn,
            since: std::time::Instant::now(),
        });
    }
}

#[cfg(test)]
mod tests;

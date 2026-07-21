use crate::command::{SessionExportFormat, SessionsCommand};
use crate::presentation::{sessions_list_output, sessions_prune_output, sessions_show_output};
use anyhow::{Context, Result};
use kuzushi_core::session_transcript::{
    render_session_markdown, SessionListOptions, SessionPruneOptions, SessionReadResult,
    SessionTranscriptStore,
};
use kuzushi_core::ConfigPaths;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub(crate) fn sessions_command(
    command: SessionsCommand,
    global_target: Option<PathBuf>,
) -> Result<()> {
    let paths = ConfigPaths::from_target(None)?;
    let store = SessionTranscriptStore::for_home(paths.home_dir);
    dispatch_sessions_command(&store, command, global_target)
}

fn dispatch_sessions_command(
    store: &SessionTranscriptStore,
    command: SessionsCommand,
    global_target: Option<PathBuf>,
) -> Result<()> {
    reject_target_filter_for_non_list(&command, global_target.as_ref())?;
    match command {
        SessionsCommand::List { json } => sessions_list_command(store, global_target, json),
        SessionsCommand::Show { session_id, json } => {
            sessions_show_command(store, &session_id, json)
        }
        SessionsCommand::Export {
            session_id,
            format,
            output,
        } => sessions_export_command(store, &session_id, format, &output),
        SessionsCommand::Prune {
            older_than_days,
            dry_run,
            json,
        } => sessions_prune_command(store, older_than_days, dry_run, json),
    }
}

fn reject_target_filter_for_non_list(
    command: &SessionsCommand,
    global_target: Option<&PathBuf>,
) -> Result<()> {
    if global_target.is_none() || matches!(command, SessionsCommand::List { .. }) {
        return Ok(());
    }
    anyhow::bail!(
        "--target filters `kuzushi sessions list` only; show and export use a globally unique session id, and prune applies to the global session store"
    )
}

fn sessions_list_command(
    store: &SessionTranscriptStore,
    target: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let options = SessionListOptions {
        target: normalize_target_filter(target)?,
    };
    let sessions = store.list(&options)?;
    print!("{}", sessions_list_output(store.root(), &sessions, json)?);
    Ok(())
}

fn normalize_target_filter(target: Option<PathBuf>) -> Result<Option<PathBuf>> {
    let Some(target) = target else {
        return Ok(None);
    };
    let absolute = if target.is_absolute() {
        target
    } else {
        std::env::current_dir()
            .context("Could not resolve current directory for --target")?
            .join(target)
    };
    Ok(Some(fs::canonicalize(&absolute).unwrap_or(absolute)))
}

fn sessions_show_command(
    store: &SessionTranscriptStore,
    session_id: &str,
    json: bool,
) -> Result<()> {
    let session = store
        .read(session_id)
        .with_context(|| format!("Could not read session {session_id:?}"))?;
    print!("{}", sessions_show_output(&session, json)?);
    Ok(())
}

fn sessions_export_command(
    store: &SessionTranscriptStore,
    session_id: &str,
    format: SessionExportFormat,
    output: &Path,
) -> Result<()> {
    let session = store
        .read(session_id)
        .with_context(|| format!("Could not export session {session_id:?}"))?;
    let body = session_export_body(&session, format);
    write_private_export(output, body.as_bytes())?;
    println!("Exported session {session_id} to {}", output.display());
    Ok(())
}

fn session_export_body(session: &SessionReadResult, format: SessionExportFormat) -> String {
    match format {
        SessionExportFormat::Jsonl => session.raw_jsonl.clone(),
        SessionExportFormat::Markdown => render_session_markdown(session),
    }
}

fn write_private_export(output: &Path, body: &[u8]) -> Result<()> {
    reject_symlink_output(output)?;
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(output)
        .with_context(|| format!("Could not open {}", output.display()))?;
    file.write_all(body)
        .with_context(|| format!("Could not write {}", output.display()))?;
    file.sync_all()
        .with_context(|| format!("Could not flush {}", output.display()))?;
    set_private_permissions(output)?;
    Ok(())
}

fn reject_symlink_output(output: &Path) -> Result<()> {
    let Ok(metadata) = fs::symlink_metadata(output) else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to export through symlink {}", output.display());
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(output: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(output, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Could not secure {}", output.display()))
}

#[cfg(not(unix))]
fn set_private_permissions(_output: &Path) -> Result<()> {
    Ok(())
}

fn sessions_prune_command(
    store: &SessionTranscriptStore,
    older_than_days: Option<u64>,
    dry_run: bool,
    json: bool,
) -> Result<()> {
    let retention_days = configured_retention_days(older_than_days)?;
    let report = store.prune(&SessionPruneOptions {
        older_than_days: retention_days,
        dry_run,
    })?;
    print!("{}", sessions_prune_output(&report, json)?);
    Ok(())
}

fn configured_retention_days(override_days: Option<u64>) -> Result<u64> {
    if let Some(days) = override_days {
        if days == 0 {
            anyhow::bail!("--older-than-days must be greater than zero");
        }
        return Ok(days);
    }
    Ok(super::config_diagnostics::load_cli_config(None)?
        .operator
        .session_retention_days)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::session_transcript::{SessionStatus, SessionSummary};

    #[test]
    fn zero_day_prune_override_is_rejected() {
        let error = configured_retention_days(Some(0)).unwrap_err().to_string();
        assert!(error.contains("greater than zero"), "{error}");
    }

    #[test]
    fn session_target_filter_is_resolved_without_requiring_a_live_workspace() {
        let relative = normalize_target_filter(Some(PathBuf::from("deleted-target")))
            .unwrap()
            .unwrap();

        assert!(relative.is_absolute());
        assert!(relative.ends_with("deleted-target"));
    }

    #[test]
    fn session_target_filter_is_rejected_outside_list() {
        let command = SessionsCommand::Show {
            session_id: "session-1".to_string(),
            json: false,
        };

        let error = reject_target_filter_for_non_list(&command, Some(&PathBuf::from("/target")))
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("filters `kuzushi sessions list` only"),
            "{error}"
        );
    }

    #[test]
    fn jsonl_export_preserves_canonical_transcript_bytes() {
        let raw_jsonl = "{\"schemaVersion\":1}\n";
        let session = SessionReadResult {
            path: PathBuf::from("/sessions/session-1.jsonl"),
            raw_jsonl: raw_jsonl.to_string(),
            summary: SessionSummary {
                session_id: "session-1".to_string(),
                path: PathBuf::from("/sessions/session-1.jsonl"),
                started_at: "2026-07-14T12:00:00Z".to_string(),
                ended_at: None,
                status: SessionStatus::Unknown,
                process_id: 42,
                shell_mode: "scripted".to_string(),
                initial_target: None,
                current_target: None,
                event_count: 1,
                warning_count: 0,
            },
            records: Vec::new(),
            warnings: Vec::new(),
        };

        assert_eq!(
            session_export_body(&session, SessionExportFormat::Jsonl),
            raw_jsonl
        );
    }

    #[cfg(unix)]
    #[test]
    fn session_export_refuses_symlink_destination() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside.jsonl");
        let link = temp.path().join("session.jsonl");
        fs::write(&outside, "unchanged").unwrap();
        symlink(&outside, &link).unwrap();

        let error = write_private_export(&link, b"replacement").unwrap_err();
        assert!(error.to_string().contains("symlink"));
        assert_eq!(fs::read_to_string(outside).unwrap(), "unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn session_export_is_written_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("session.jsonl");

        write_private_export(&output, b"redacted transcript\n").unwrap();

        assert_eq!(
            fs::read_to_string(&output).unwrap(),
            "redacted transcript\n"
        );
        assert_eq!(
            fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

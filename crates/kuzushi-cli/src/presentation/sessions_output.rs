use anyhow::Result;
use kuzushi_core::session_transcript::{
    render_session_markdown, SessionPruneReport, SessionReadResult, SessionStatus, SessionSummary,
};
use std::path::Path;

pub(crate) fn sessions_list_output(
    root: &Path,
    sessions: &[SessionSummary],
    json: bool,
) -> Result<String> {
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(sessions)?));
    }
    Ok(sessions_list_plain(root, sessions))
}

fn sessions_list_plain(root: &Path, sessions: &[SessionSummary]) -> String {
    if sessions.is_empty() {
        return format!(
            "No shell session transcripts found at {}\nNext: kuzushi shell\n",
            root.display()
        );
    }
    let mut lines = vec![
        "Shell sessions".to_string(),
        format!("Store: {}", root.display()),
    ];
    lines.extend(sessions.iter().map(session_list_row));
    lines.push("Next: kuzushi sessions show <sessionId>".to_string());
    format!("{}\n", lines.join("\n"))
}

fn session_list_row(session: &SessionSummary) -> String {
    let target = session
        .current_target
        .as_ref()
        .or(session.initial_target.as_ref())
        .map(|target| target.display().to_string())
        .unwrap_or_else(|| "-".to_string());
    format!(
        "{}  {:<11} {} mode={} events={} warnings={} target={}",
        session.session_id,
        session_status_label(session.status),
        session.started_at,
        session.shell_mode,
        session.event_count,
        session.warning_count,
        target
    )
}

fn session_status_label(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Running => "running",
        SessionStatus::Completed => "completed",
        SessionStatus::Interrupted => "interrupted",
        SessionStatus::Unknown => "unknown",
    }
}

pub(crate) fn sessions_show_output(session: &SessionReadResult, json: bool) -> Result<String> {
    if !json {
        return Ok(render_session_markdown(session));
    }
    let value = serde_json::json!({
        "path": &session.path,
        "summary": &session.summary,
        "records": &session.records,
        "warnings": &session.warnings,
    });
    Ok(format!("{}\n", serde_json::to_string_pretty(&value)?))
}

pub(crate) fn sessions_prune_output(report: &SessionPruneReport, json: bool) -> Result<String> {
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(report)?));
    }
    let action = if report.dry_run {
        "would remove"
    } else {
        "removed"
    };
    let mut lines = vec![
        "Shell session prune".to_string(),
        format!("Examined: {}", report.examined),
        format!("{action}: {}", report.removed.len()),
        format!("Skipped live: {}", report.skipped_live.len()),
        format!("Errors: {}", report.errors.len()),
    ];
    lines.extend(
        report
            .removed
            .iter()
            .map(|path| format!("  {action} {}", path.display())),
    );
    lines.extend(
        report
            .errors
            .iter()
            .map(|error| format!("  error: {error}")),
    );
    Ok(format!("{}\n", lines.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn session_list_names_status_target_and_followup() {
        let summary = SessionSummary {
            session_id: "session-1".to_string(),
            path: PathBuf::from("/sessions/session-1.jsonl"),
            started_at: "2026-07-14T12:00:00Z".to_string(),
            ended_at: None,
            status: SessionStatus::Interrupted,
            process_id: 42,
            shell_mode: "plain_scripted".to_string(),
            initial_target: Some(PathBuf::from("/target")),
            current_target: None,
            event_count: 3,
            warning_count: 1,
        };

        let output = sessions_list_output(Path::new("/sessions"), &[summary], false).unwrap();
        assert!(output.contains("session-1  interrupted"), "{output}");
        assert!(output.contains("target=/target"), "{output}");
        assert!(output.contains("events=3 warnings=1"), "{output}");
        assert!(output.contains("sessions show <sessionId>"), "{output}");
    }

    #[test]
    fn session_prune_output_discloses_live_skips_and_errors() {
        let report = SessionPruneReport {
            examined: 4,
            removed: vec![PathBuf::from("/sessions/old.jsonl")],
            skipped_live: vec!["session-live".to_string()],
            errors: vec!["permission denied".to_string()],
            dry_run: true,
        };

        let output = sessions_prune_output(&report, false).unwrap();
        assert!(output.contains("would remove: 1"), "{output}");
        assert!(output.contains("Skipped live: 1"), "{output}");
        assert!(output.contains("Errors: 1"), "{output}");
        assert!(output.contains("permission denied"), "{output}");
    }
}

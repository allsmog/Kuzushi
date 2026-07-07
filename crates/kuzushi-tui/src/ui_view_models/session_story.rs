use crate::{LogLine, ScanPanelState, ShellApp};

pub(crate) const COMMAND_HISTORY_COLUMN_COUNT: usize = 2;
pub(crate) const SESSION_STORY_COLUMN_COUNT: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandHistoryModel {
    pub(crate) rows: Vec<CommandHistoryRow>,
    pub(crate) number_width: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandHistoryRow {
    pub(crate) cells: [String; COMMAND_HISTORY_COLUMN_COUNT],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionStoryModel {
    pub(crate) scan_row: Option<SessionStoryRow>,
    pub(crate) events: Vec<SessionStoryRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionStoryRow {
    pub(crate) cells: [String; SESSION_STORY_COLUMN_COUNT],
}

pub(crate) fn session_history_model(app: &ShellApp, visible_count: usize) -> CommandHistoryModel {
    history_model_from_commands(app.command_history(), visible_count)
}

pub(crate) fn session_story_model(app: &ShellApp, visible_count: usize) -> SessionStoryModel {
    SessionStoryModel {
        scan_row: app
            .scan()
            .map(|scan| scan_story_row(scan, app.is_scan_paused())),
        events: story_event_rows(app.log_lines(), visible_count),
    }
}

fn history_model_from_commands(commands: &[String], visible_count: usize) -> CommandHistoryModel {
    let start = commands.len().saturating_sub(visible_count);
    let rows = commands
        .iter()
        .skip(start)
        .enumerate()
        .map(|(offset, command)| CommandHistoryRow {
            cells: [(start + offset + 1).to_string(), command.clone()],
        })
        .collect::<Vec<_>>();
    CommandHistoryModel {
        number_width: command_number_width(commands.len()),
        rows,
    }
}

fn command_number_width(command_count: usize) -> usize {
    command_count.max(1).to_string().len()
}

fn scan_story_row(scan: &ScanPanelState, paused: bool) -> SessionStoryRow {
    let label = if scan.running {
        running_scan_label(scan, paused)
    } else {
        "idle"
    };
    SessionStoryRow {
        cells: [
            "scan".to_string(),
            format!(
                "{label} · stage={} · findings={}",
                scan.stage, scan.findings_count
            ),
        ],
    }
}

fn running_scan_label(scan: &ScanPanelState, paused: bool) -> &'static str {
    if scan.abort_requested {
        "abort requested"
    } else if paused {
        "paused"
    } else {
        "running"
    }
}

fn story_event_rows(log: &[LogLine], visible_count: usize) -> Vec<SessionStoryRow> {
    let rows = log
        .iter()
        .filter(|line| line.prefix != ">")
        .map(SessionStoryRow::from_log_line)
        .collect::<Vec<_>>();
    let start = rows.len().saturating_sub(visible_count);
    rows.into_iter().skip(start).collect()
}

impl SessionStoryRow {
    fn from_log_line(line: &LogLine) -> Self {
        Self {
            cells: [line.prefix.clone(), line.body.clone()],
        }
    }
}

#[cfg(test)]
mod tests;

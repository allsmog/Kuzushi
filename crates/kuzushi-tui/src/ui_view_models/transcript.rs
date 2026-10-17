use crate::{LogLine, ShellApp};
mod command_echo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TranscriptModel {
    pub(crate) rows: Vec<TranscriptRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TranscriptRow {
    pub(crate) prefix: String,
    pub(crate) body: String,
    pub(crate) continuation: bool,
    pub(crate) time_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainCommandResultModel {
    pub(crate) result_title: &'static str,
    pub(crate) rows: Vec<String>,
    pub(crate) view_title: &'static str,
}

pub(crate) fn transcript_model(app: &ShellApp, visible_count: usize) -> TranscriptModel {
    TranscriptModel {
        rows: transcript_rows(app.log_lines(), visible_count),
    }
}

pub(crate) fn transcript_model_from_log_index(app: &ShellApp, log_start: usize) -> TranscriptModel {
    let log_start = log_start.min(app.log_len());
    TranscriptModel {
        rows: transcript_rows_all(&app.log_lines()[log_start..]),
    }
}

/// The full-screen Logs document: everything durably recorded for this session
/// ahead of everything still in the live cache, narrowed by the active filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogsModel {
    pub(crate) rows: Vec<TranscriptRow>,
    pub(crate) summary: String,
    pub(crate) notice: Option<String>,
}

pub(crate) fn logs_model(app: &ShellApp) -> LogsModel {
    build_logs_model(app, app.router.logs().command_text_expanded())
}

pub(crate) fn plain_logs_lines(app: &ShellApp) -> Vec<String> {
    let model = build_logs_model(app, true);
    let mut lines = vec!["LOGS".into(), model.summary];
    lines.extend(model.notice);
    lines.extend(model.rows.into_iter().map(plain_transcript_row));
    lines
}

fn build_logs_model(app: &ShellApp, expanded: bool) -> LogsModel {
    let route = app.router.logs();
    let history = route.history();
    let live = app.log_lines();
    let earlier = history.lines_before_live(live.len());
    let total = earlier.len() + live.len();
    let lines = earlier
        .iter()
        .chain(live.iter())
        .filter(|line| matches_query(line, route.query()))
        .cloned()
        .collect::<Vec<_>>();
    LogsModel {
        summary: logs_summary(total, earlier.len(), lines.len(), route.query()),
        notice: logs_notice(history.error(), lines.is_empty(), route.query()),
        rows: command_echo::rows(
            &lines,
            expanded,
            route.reader_open(),
            route.query().is_some(),
        ),
    }
}

fn matches_query(line: &LogLine, query: Option<&str>) -> bool {
    let Some(query) = query else {
        return true;
    };
    let query = query.to_lowercase();
    line.body.to_lowercase().contains(&query) || line.prefix.to_lowercase().contains(&query)
}

fn logs_summary(total: usize, earlier: usize, shown: usize, query: Option<&str>) -> String {
    let recovered = if earlier > 0 {
        format!(" · {earlier} from the session file")
    } else {
        String::new()
    };
    match query {
        Some(query) => format!("{shown}/{total} log lines match \"{query}\"{recovered}"),
        None => format!("{total} log lines{recovered}"),
    }
}

fn logs_notice(error: Option<&str>, empty: bool, query: Option<&str>) -> Option<String> {
    if let Some(error) = error {
        return Some(format!("earlier lines unavailable: {error}"));
    }
    match (empty, query) {
        (true, Some(query)) => Some(format!("no log lines match \"{query}\" — Esc clears it")),
        _ => None,
    }
}

fn transcript_rows(log: &[LogLine], visible_count: usize) -> Vec<TranscriptRow> {
    if visible_count == 0 {
        return Vec::new();
    }
    let rows = transcript_rows_all(log);
    let start = rows.len().saturating_sub(visible_count);
    rows.into_iter().skip(start).collect()
}

fn transcript_rows_all(log: &[LogLine]) -> Vec<TranscriptRow> {
    log.iter().flat_map(TranscriptRow::from_log_line).collect()
}

impl TranscriptRow {
    fn from_log_line(line: &LogLine) -> Vec<Self> {
        body_segments(&line.body)
            .into_iter()
            .enumerate()
            .map(|(index, body)| Self {
                prefix: line.prefix.clone(),
                body,
                continuation: index > 0,
                time_secs: line.time_secs,
            })
            .collect()
    }
}

pub(crate) fn plain_command_result_model(
    app: &ShellApp,
    command: &str,
    log_start: usize,
) -> PlainCommandResultModel {
    let mut rows = vec![format!("command: {command}"), "logs:".to_string()];
    rows.extend(
        transcript_model_from_log_index(app, log_start)
            .rows
            .into_iter()
            .map(plain_transcript_row),
    );
    PlainCommandResultModel {
        result_title: "COMMAND RESULT",
        rows,
        view_title: "VIEW",
    }
}

fn plain_transcript_row(row: TranscriptRow) -> String {
    if row.continuation {
        return format!("  {}", row.body);
    }
    if row.prefix == ">" {
        format!("> {}", row.body)
    } else {
        format!("{}: {}", row.prefix, row.body)
    }
}

fn body_segments(body: &str) -> Vec<String> {
    if body.is_empty() {
        vec![String::new()]
    } else {
        body.lines().map(str::to_string).collect()
    }
}

#[cfg(test)]
mod tests;

use crate::{LogLine, ShellApp};

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
        rows: transcript_rows(&app.log, visible_count),
    }
}

pub(crate) fn transcript_model_from_log_index(app: &ShellApp, log_start: usize) -> TranscriptModel {
    let log_start = log_start.min(app.log.len());
    TranscriptModel {
        rows: transcript_rows_all(&app.log[log_start..]),
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

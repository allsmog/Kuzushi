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

pub(crate) fn transcript_model(app: &ShellApp, visible_count: usize) -> TranscriptModel {
    TranscriptModel {
        rows: transcript_rows(&app.log, visible_count),
    }
}

fn transcript_rows(log: &[LogLine], visible_count: usize) -> Vec<TranscriptRow> {
    if visible_count == 0 {
        return Vec::new();
    }
    let rows = log
        .iter()
        .flat_map(TranscriptRow::from_log_line)
        .collect::<Vec<_>>();
    let start = rows.len().saturating_sub(visible_count);
    rows.into_iter().skip(start).collect()
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

fn body_segments(body: &str) -> Vec<String> {
    if body.is_empty() {
        vec![String::new()]
    } else {
        body.lines().map(str::to_string).collect()
    }
}

#[cfg(test)]
mod tests;

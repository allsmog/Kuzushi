use super::scan_status;
use crate::{ActorDetailFilter, LogLine, ShellApp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActorDetailModel {
    pub(crate) status: String,
    pub(crate) filter_label: String,
    pub(crate) transcript: Vec<ActorTranscriptRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActorTranscriptRow {
    pub(crate) prefix: String,
    pub(crate) body: String,
}

pub(crate) fn actor_detail_model(app: &ShellApp, visible_count: usize) -> ActorDetailModel {
    let filter = app.router.actor_detail().filter();
    ActorDetailModel {
        status: actor_status(app),
        filter_label: filter.label().to_string(),
        transcript: visible_transcript_rows(app.log_lines(), filter, visible_count),
    }
}

fn actor_status(app: &ShellApp) -> String {
    app.scan()
        .map(scan_status)
        .unwrap_or_else(|| "idle".to_string())
}

fn visible_transcript_rows(
    log: &[LogLine],
    filter: ActorDetailFilter,
    visible_count: usize,
) -> Vec<ActorTranscriptRow> {
    let rows = log
        .iter()
        .filter(|line| filter.keeps(&line.prefix))
        .map(ActorTranscriptRow::from_log_line)
        .collect::<Vec<_>>();
    let start = rows.len().saturating_sub(visible_count);
    rows.into_iter().skip(start).collect()
}

impl ActorTranscriptRow {
    fn from_log_line(line: &LogLine) -> Self {
        Self {
            prefix: line.prefix.clone(),
            body: line.body.clone(),
        }
    }
}

#[cfg(test)]
mod tests;

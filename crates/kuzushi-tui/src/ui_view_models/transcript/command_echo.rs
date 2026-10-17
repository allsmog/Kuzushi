use super::*;
use kuzushi_core::run_lifecycle::SafeText;

pub(super) fn rows(
    lines: &[LogLine],
    expanded: bool,
    reading: bool,
    filtering: bool,
) -> Vec<TranscriptRow> {
    lines
        .iter()
        .flat_map(|line| {
            let folded = (!expanded)
                .then(|| fold(line, reading, filtering))
                .flatten();
            TranscriptRow::from_log_line(folded.as_ref().unwrap_or(line))
        })
        .collect()
}

fn fold(line: &LogLine, reading: bool, filtering: bool) -> Option<LogLine> {
    if line.prefix != ">" {
        return None;
    }
    let characters = line.body.chars().count();
    let count = line.body.lines().count();
    if characters <= 240 && count <= 4 {
        return None;
    }
    let control = if reading {
        "c reads command text"
    } else {
        "z, then c reads command text"
    };
    let matched = if filtering { "filter match; " } else { "" };
    let line_label = if count == 1 { "line" } else { "lines" };
    Some(LogLine {
        prefix: line.prefix.clone(),
        time_secs: line.time_secs,
        body: format!(
            "{} · {characters} chars, {count} {line_label} · command folded · {matched}{control}",
            title(&line.body)
        ),
    })
}

fn title(command: &str) -> String {
    let mut words = command.split_whitespace();
    let verb = words.next().unwrap_or("command");
    let title = if verb.trim_start_matches('/') == "run" {
        format!("{verb} {}", words.next().unwrap_or(""))
    } else {
        verb.to_string()
    };
    let safe = SafeText::operator_visible(title);
    let mut text = safe.as_str().chars().take(64).collect::<String>();
    if safe.as_str().chars().count() > 64 {
        text.push('…');
    }
    text
}

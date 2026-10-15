//! Read-only projection for captured code and an explicit human decision.
use crate::app::source_review::{SourceReviewForm, SourceReviewMode, SOURCE_VERDICTS};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

pub(crate) fn source_review_wrapped_lines(form: &SourceReviewForm, width: usize) -> Vec<String> {
    let mut lines = form.notice.clone().into_iter().collect::<Vec<_>>();
    lines.extend(source_review_lines(form));
    let literal = matches!(
        form.mode,
        SourceReviewMode::Reading | SourceReviewMode::Saved
    ) && !form.show_source_receipt;
    lines
        .into_iter()
        .flat_map(|line| {
            if literal {
                wrap_code_line(&line, width)
            } else {
                crate::renderer::shared::text::wrap_text(&line, width)
            }
        })
        .collect()
}

pub(super) fn wrap_code_line(line: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut rows = Vec::new();
    let mut current = String::new();
    let mut columns = 0;
    for grapheme in line.graphemes(true) {
        let cells = grapheme.width();
        if columns + cells > width && !current.is_empty() {
            rows.push(std::mem::take(&mut current));
            columns = 0;
        }
        current.push_str(grapheme);
        columns += cells;
    }
    rows.push(current);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captured_code_wrap_preserves_indentation_and_unicode_graphemes() {
        let source = "   2 │     if 東京 == e\u{301}:";
        let rows = wrap_code_line(source, 12);
        assert_eq!(rows.concat(), source);
        assert!(rows.iter().all(|row| row.width() <= 12));
        assert!(!rows.iter().any(|row| row.starts_with('\u{301}')));
    }
    #[test]
    fn code_controls_are_displayed_as_text_without_terminal_sequences() {
        assert_eq!(display_code("a\x1b[31mb\t"), "a�[31mb ");
    }
}

pub(crate) fn source_review_title(form: &SourceReviewForm) -> &'static str {
    match form.mode {
        SourceReviewMode::Intro => "REVIEW CURRENT SOURCE",
        SourceReviewMode::Capturing => "CAPTURING CURRENT SOURCE",
        SourceReviewMode::Reading => "READ CAPTURED SOURCE",
        SourceReviewMode::Verdict => "CHOOSE SOURCE VERDICT",
        SourceReviewMode::Reason => "EXPLAIN SOURCE VERDICT",
        SourceReviewMode::Confirm => "REVIEW SOURCE DECISION",
        SourceReviewMode::Saving => "SAVING SOURCE DECISION",
        SourceReviewMode::Saved => "SOURCE DECISION SAVED",
    }
}

pub(crate) fn source_review_controls(mode: SourceReviewMode) -> &'static str {
    match mode {
        SourceReviewMode::Intro => "Enter capture · Esc back\nPgUp/PgDn inspect limits",
        SourceReviewMode::Capturing | SourceReviewMode::Saving => "Esc request cancel and return",
        SourceReviewMode::Reading => {
            "Enter verdict · Tab code/source\nPgUp/PgDn · r new · Esc back"
        }
        SourceReviewMode::Saved => "Tab code/source · PgUp/PgDn\nr new capture · Esc back",
        SourceReviewMode::Verdict => "↑/↓ choose · Enter reason · Esc code",
        SourceReviewMode::Reason => "Ctrl+S review · Enter newline\nEsc verdict · arrows edit",
        SourceReviewMode::Confirm => "Enter save · Esc edit\nPgUp/PgDn inspect the receipt",
    }
}

pub(crate) fn source_review_lines(form: &SourceReviewForm) -> Vec<String> {
    match form.mode {
        SourceReviewMode::Intro => intro_lines(),
        SourceReviewMode::Capturing => vec![
            "Capturing bounded source identity and cited code.".into(),
            "No provider requests. Waiting for the captured-source receipt.".into(),
        ],
        SourceReviewMode::Verdict => SOURCE_VERDICTS
            .iter()
            .enumerate()
            .map(|(i, (_, label))| format!("{} {label}", if i == form.verdict { "▸" } else { " " }))
            .collect(),
        SourceReviewMode::Reason => vec![format!("Verdict: {}", SOURCE_VERDICTS[form.verdict].1)],
        SourceReviewMode::Confirm => confirmation_lines(form),
        SourceReviewMode::Saving => vec![
            "Saving the explicit human decision.".into(),
            "The captured source and ledger cutoff are checked again before the write.".into(),
        ],
        _ => captured_code_lines(form),
    }
}

fn intro_lines() -> Vec<String> {
    vec!["Capture this target's current source before deciding.".into(),
        "This action makes no scan observations or provider requests.".into(),
        "Two bounded identity walks, up to 1,000,000 files and 16 GiB each.".into(),
        "Capture at most 256 KiB of the complete cited file. Larger or unavailable files are disclosed.".into(),
        "Ignored and symlink material is excluded. This is not a complete repository copy.".into(),
        "Then read the frozen code, choose a verdict, add a reason and review the save.".into()]
}

fn captured_code_lines(form: &SourceReviewForm) -> Vec<String> {
    if form.show_source_receipt {
        return source_receipt_lines(form);
    }
    let Some(capture) = &form.capture else {
        return vec!["No captured source is available.".into()];
    };
    let mut lines = vec![
        format!("Captured file: {}", form.file),
        "Frozen code from the captured source; not a live checkout read.".into(),
    ];
    match capture["citedSourceCode"].as_str() {
        Some("") => lines.push("Captured file is empty.".into()),
        Some(code) => lines.extend(
            code.lines()
                .enumerate()
                .map(|(i, line)| format!("{:>4} │ {}", i + 1, display_code(line))),
        ),
        None => lines.push(format!(
            "Cited code unavailable: {}.",
            capture["reviewedSource"]["citedFile"]["state"]
                .as_str()
                .unwrap_or("legacy capture without code")
        )),
    }
    lines
}

pub(crate) fn source_receipt_lines(form: &SourceReviewForm) -> Vec<String> {
    let Some(capture) = &form.capture else {
        return vec!["No captured source is available.".into()];
    };
    let source = &capture["reviewedSource"];
    vec![
        format!(
            "Source reference: {}",
            capture["sourceRef"].as_str().unwrap_or("unavailable")
        ),
        format!(
            "Captured: {}",
            super::recorded_timestamp_label(source["capturedAt"].as_str().unwrap_or("unavailable"))
        ),
        format!(
            "Commit: {}",
            source["sourceGit"]["sha"]
                .as_str()
                .unwrap_or("not recorded")
        ),
        format!("Dirty: {}", source["sourceGit"]["dirty"]),
        format!(
            "Snapshot: {}",
            source["snapshotHash"].as_str().unwrap_or("unavailable")
        ),
        format!(
            "Content: {}",
            source["treeHash"].as_str().unwrap_or("unavailable")
        ),
        "Identity excludes ignored and symlink material. It does not establish a fix.".into(),
    ]
}

fn confirmation_lines(form: &SourceReviewForm) -> Vec<String> {
    let mut lines = vec![
        format!("Verdict: {}", SOURCE_VERDICTS[form.verdict].1),
        "Reason:".into(),
    ];
    lines.extend(form.reason.text().lines().map(str::to_owned));
    lines.push("Save one human decision against this exact capture. Earlier observations and decisions remain in history.".into());
    lines.extend(source_receipt_lines(form));
    lines
}

fn display_code(line: &str) -> String {
    line.chars()
        .map(|ch| {
            if ch == '\t' {
                ' '
            } else if ch.is_control() {
                '�'
            } else {
                ch
            }
        })
        .collect()
}

pub(crate) fn source_review_plain_lines(form: &SourceReviewForm) -> Vec<String> {
    let mut lines = vec![
        source_review_title(form).into(),
        format!(
            "Finding generation {} · {}:{}",
            form.finding_id, form.file, form.line
        ),
    ];
    lines.extend(source_review_lines(form));
    if form.mode == SourceReviewMode::Reason {
        lines.extend(form.reason.text().lines().map(str::to_owned));
    }
    lines.extend(form.notice.clone());
    lines.push(source_review_controls(form.mode).into());
    lines
}

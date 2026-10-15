//! An explicit choice of local drafts; restoration never approves work.
use crate::app::{ShellApp, StudyDraftRecovery};
use crate::renderer::shared::text::{fit, wrap_text};

pub(crate) fn title(recovery: &StudyDraftRecovery) -> &'static str {
    if *recovery == StudyDraftRecovery::Discard {
        "LEAVE UNSAVED STUDY"
    } else {
        "RECOVER STUDY DRAFT"
    }
}

pub(crate) fn hint(recovery: &StudyDraftRecovery) -> &'static str {
    match recovery {
        StudyDraftRecovery::Choices { .. } => "↑↓ select · Enter restore · n new · Esc back",
        StudyDraftRecovery::Failed(_) => "Enter retry · n new · Esc back",
        StudyDraftRecovery::Discard => "Enter/Esc stay · d discard choices",
        _ => "Esc back",
    }
}

pub(crate) fn lines(app: &ShellApp, width: usize, height: usize) -> Option<Vec<String>> {
    if !app.study_draft_recovery_open() || app.advisory().pending_confirm.is_some() {
        return None;
    }
    let recovery = &app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()?
        .draft_recovery;
    let lines = match recovery {
        StudyDraftRecovery::Loading => vec!["Reading and validating local study choices…".into()],
        StudyDraftRecovery::Failed(error) => wrap_text(
            &format!("Recovery unavailable: {error}. Original drafts retained."),
            width,
        ),
        StudyDraftRecovery::Choices { drafts, cursor } => {
            choice_lines(drafts, *cursor, width, height)
        }
        StudyDraftRecovery::None => return None,
        StudyDraftRecovery::Discard => discard_lines(),
    };
    Some(lines)
}

fn discard_lines() -> Vec<String> {
    [
        "These edits are not saved.",
        "Stay to keep them.",
        "Discard removes this draft.",
        "Recorded work stays unchanged.",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn choice_lines(
    drafts: &[crate::app::RecoveredStudyDraft],
    cursor: usize,
    width: usize,
    height: usize,
) -> Vec<String> {
    let mut lines = vec![format!("Saved drafts: {}", drafts.len())];
    let count = height.saturating_sub(3).max(1).min(drafts.len());
    let start = cursor.saturating_sub(count.saturating_sub(1));
    for (index, draft) in drafts.iter().enumerate().skip(start).take(count) {
        let (label, suffix) = choice_workload(draft);
        let prefix = if index == cursor { "▸ " } else { "  " };
        let available = width.saturating_sub(prefix.chars().count() + suffix.chars().count());
        lines.push(format!("{prefix}{}{suffix}", fit(&label, available)));
    }
    append_selected_details(&mut lines, &drafts[cursor], width);
    lines.push("Prepare a fresh plan before approval.".into());
    lines
}

fn append_selected_details(
    lines: &mut Vec<String>,
    draft: &crate::app::RecoveredStudyDraft,
    width: usize,
) {
    if let Some(baseline) = draft.cases().into_iter().find(|case| case.2) {
        lines.push(fit(&format!("Baseline: {}", baseline.0), width));
    }
    append_draft_text(lines, "Name draft", draft.name_draft(), width);
    append_draft_text(lines, "Goal draft", draft.goal_draft(), width);
}

fn choice_workload(draft: &crate::app::RecoveredStudyDraft) -> (String, String) {
    let cases = draft.cases();
    if !cases.is_empty() {
        let passes: usize = cases.iter().map(|case| case.1).sum();
        return (
            cases
                .iter()
                .map(|c| c.0.as_str())
                .collect::<Vec<_>>()
                .join(" / "),
            format!(" · {} cases · {passes} passes", cases.len()),
        );
    }
    scope_workload(draft)
}

fn scope_workload(draft: &crate::app::RecoveredStudyDraft) -> (String, String) {
    let scopes = draft.scope_labels();
    if !scopes.is_empty() {
        let passes: usize = scopes.iter().map(|s| s.1).sum();
        return (
            scopes
                .iter()
                .map(|s| s.0.as_str())
                .collect::<Vec<_>>()
                .join(" / "),
            format!(" · {} scopes · {passes} passes", scopes.len()),
        );
    }
    let label = if draft.has_selected_scope() {
        "Selected scope"
    } else {
        "Whole repository"
    };
    (label.into(), format!(" · {} passes", draft.repetitions()))
}

fn append_draft_text(lines: &mut Vec<String>, label: &str, text: Option<&str>, width: usize) {
    let Some(text) = text else {
        return;
    };
    let readable: String = text
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    lines.push(fit(&format!("{label}: {readable}"), width));
}

pub(crate) fn plain_lines(app: &ShellApp, width: usize) -> Option<Vec<String>> {
    let mut lines = lines(app, width, 128)?;
    let recovery = &app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()?
        .draft_recovery;
    lines.insert(0, title(recovery).into());
    lines.push(hint(recovery).into());
    Some(lines)
}

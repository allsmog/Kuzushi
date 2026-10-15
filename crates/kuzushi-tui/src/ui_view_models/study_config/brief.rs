use crate::app::{BatchScanConfig, BriefEditor, BriefMode};
use crate::renderer::shared::text::wrap_text;

pub(crate) fn title(mode: BriefMode) -> &'static str {
    match mode {
        BriefMode::Writing => "WRITE INVESTIGATION BRIEF",
        BriefMode::Review => "REVIEW BRIEF REVISION",
        BriefMode::Saving => "SAVING BRIEF",
        BriefMode::Loading | BriefMode::Read => "INVESTIGATION BRIEF",
    }
}

pub(crate) fn controls(mode: BriefMode, narrow: bool) -> &'static str {
    match mode {
        BriefMode::Writing => "Ctrl+S review · Enter newline · Esc back",
        BriefMode::Review => "Enter save/use · e edit · Esc back",
        BriefMode::Loading | BriefMode::Saving => "Esc back · no model calls",
        BriefMode::Read if narrow => "e edit · a use · r reload · Esc back",
        BriefMode::Read => "e edit · a use · r reload · ↑↓/PgUp/Dn · Esc back",
    }
}

pub(crate) fn notice_lines(editor: &BriefEditor, checkpoint: Option<&str>) -> Vec<String> {
    let lines: Vec<_> = [editor.notice.as_deref(), checkpoint]
        .into_iter()
        .flatten()
        .map(str::to_owned)
        .collect();
    if lines.is_empty() {
        vec!["Goal and priorities · no work approval".into()]
    } else {
        lines
    }
}

pub(crate) fn reading_lines(editor: &BriefEditor, width: usize) -> Vec<String> {
    let mut lines = vec![format!("Shown revision: {}", editor.loaded.as_ref().map_or("not saved".into(), |brief| brief.reference.revision.to_string())),
        "Operator intent guides planning and priorities. Source evidence decides findings. No model context, work or allowance changes.".into()];
    if editor
        .loaded
        .as_ref()
        .is_some_and(|brief| brief.document.text != editor.editor.text())
    {
        lines.push(
            "Unsaved text differs from this revision. Review and save before selecting it.".into(),
        );
    }
    if editor.mode == BriefMode::Review {
        lines.push("Previous accepted text".into());
        lines.push(
            editor
                .loaded
                .as_ref()
                .map_or("No prior brief".into(), |brief| brief.document.text.clone()),
        );
        lines.push("Reviewed text to save and use for a new study".into());
    }
    lines.push(editor.editor.text().into());
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width))
        .collect()
}

pub(crate) fn selected_lines(config: &BatchScanConfig) -> Vec<String> {
    let Some(brief) = &config.study.brief else {
        return vec!["Optional operator goal, priorities and open questions. Enter reads the saved target-local brief. Saving and selecting a revision approves no work or allowance and changes no model prompt or finding verdict.".into()];
    };
    vec![format!("Exact brief revision {} · {}", brief.reference.revision, brief.reference.brief_id),
        brief.document.text.clone(), "This revision is retained with the approved plan. Later edits do not change frozen jobs or finding verdicts.".into()]
}

pub(crate) fn plain_lines(editor: &BriefEditor, width: usize) -> Vec<String> {
    let mut lines = vec![title(editor.mode).into()];
    lines.extend(notice_lines(editor, None));
    lines.extend(reading_lines(editor, width));
    lines.push(controls(editor.mode, width < 44).into());
    lines
}

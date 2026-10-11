use crate::renderer::shared::text::wrap_text;
use crate::ShellApp;

pub(crate) struct ResourcePickerModel {
    pub(crate) choices: Vec<String>,
    pub(crate) detail: Vec<String>,
    pub(crate) max_offset: usize,
    pub(crate) page_rows: usize,
    pub(crate) list_rows: usize,
}

pub(crate) fn resource_picker_model(
    app: &ShellApp,
    width: usize,
    rows: usize,
) -> Option<ResourcePickerModel> {
    let picker = app.study_resource_picker()?;
    let body_rows = rows.saturating_sub(6);
    let list_rows = (body_rows / 3).clamp(1, 8).min(body_rows);
    let page_rows = body_rows.saturating_sub(list_rows + 1);
    let choices = choice_rows(picker, list_rows);
    let detail = detail_document(picker, width)?;
    let max_offset = detail.len().saturating_sub(page_rows);
    let detail = detail
        .into_iter()
        .skip(picker.scroll.min(max_offset))
        .take(page_rows)
        .collect();
    Some(ResourcePickerModel {
        choices,
        detail,
        max_offset,
        page_rows,
        list_rows,
    })
}

fn choice_rows(picker: &crate::app::StudyResourcePicker, rows: usize) -> Vec<String> {
    let start = picker.cursor.saturating_sub(rows.saturating_sub(1));
    picker
        .choices
        .iter()
        .enumerate()
        .skip(start)
        .take(rows)
        .map(|(index, choice)| {
            format!(
                "{} {}",
                if index == picker.cursor { "▸" } else { " " },
                choice.label
            )
        })
        .collect()
}

fn detail_document(picker: &crate::app::StudyResourcePicker, width: usize) -> Option<Vec<String>> {
    let selected = picker.choices.get(picker.cursor)?;
    let mut detail = vec![selected.campaign_id.as_ref().map_or_else(
        || "No historical calibration selected.".into(),
        |id| format!("Prior study: {id}"),
    )];
    detail.extend(history_lines(&picker.history));
    detail.extend(["Only complete passes with matching source, context, engine, model and runtime calibrate each case. Missing evidence and prices stay unknown.".into(),
        "Preparing the new draft reads this named study once. It starts no jobs or model requests and preserves existing spending.".into(),
        "History reads are bounded to 1,000 directory entries, 100 retained studies and 32 MiB of metadata, with 1 MiB per file. A named selection outside this window remains available.".into()]);
    Some(
        detail
            .iter()
            .flat_map(|line| wrap_text(line, width.max(1)))
            .collect(),
    )
}

fn history_lines(state: &crate::app::ViewDataState<crate::app::StudyHistoryRead>) -> Vec<String> {
    use crate::app::ViewDataState;
    match state {
        ViewDataState::Ready(Ok(catalogue))=>vec![format!("History: {} choices · {} entries visited · {} unreadable · {} symlinks skipped.",catalogue.choices.len(),catalogue.visited_entries,catalogue.unreadable_entries,catalogue.skipped_symlinks),
            history_completeness(catalogue)],
        ViewDataState::Ready(Err(error))=>vec![format!("History unavailable: {error}. r refreshes; the draft and existing choice remain unchanged.")],
        _=>vec!["Loading bounded study history in the background. Keep navigating or Esc to cancel; earlier choices remain visible.".into()],
    }
}

fn history_completeness(
    catalogue: &kuzushi_core::capabilities::campaign::StudyUsageCatalogue,
) -> String {
    if catalogue.entry_limit_reached
        || catalogue.byte_limit_reached
        || catalogue.choice_limit_reached
    {
        return format!("Partial history: entry limit {}, byte limit {}, choice limit {}. Earlier study evidence is not excluded from named-plan recovery.",catalogue.entry_limit_reached,catalogue.byte_limit_reached,catalogue.choice_limit_reached);
    }
    "History enumeration completed within the read limits. Counts are recorded progress; preparation still authenticates calibration conditions.".into()
}

pub(crate) fn resource_picker_document(app: &ShellApp, width: usize) -> Option<Vec<String>> {
    let picker = app.study_resource_picker()?;
    let mut lines = choice_rows(picker, picker.choices.len());
    lines.extend(detail_document(picker, width)?);
    Some(lines)
}

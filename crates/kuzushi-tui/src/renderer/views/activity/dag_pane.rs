use super::*;
use crate::ui_view_models::ActivityDagRowTone;

pub(crate) fn dag_row_style(tone: ActivityDagRowTone) -> ratatui::style::Style {
    match tone {
        ActivityDagRowTone::Done => theme::success(),
        ActivityDagRowTone::Active => theme::warn(),
        ActivityDagRowTone::Queued => theme::muted(),
        ActivityDagRowTone::Failing => theme::danger(),
        ActivityDagRowTone::Muted => theme::muted(),
    }
}

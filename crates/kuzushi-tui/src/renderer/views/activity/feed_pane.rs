use super::*;
use crate::ui_view_models::ActivityFeedRowTone;

pub(crate) fn feed_row_style(tone: ActivityFeedRowTone) -> ratatui::style::Style {
    match tone {
        ActivityFeedRowTone::Primary => theme::primary(),
        ActivityFeedRowTone::Success => theme::success(),
        ActivityFeedRowTone::Muted => theme::muted(),
        ActivityFeedRowTone::Danger => theme::danger(),
        ActivityFeedRowTone::Warn => theme::warn(),
        ActivityFeedRowTone::Subtle => theme::subtle(),
    }
}

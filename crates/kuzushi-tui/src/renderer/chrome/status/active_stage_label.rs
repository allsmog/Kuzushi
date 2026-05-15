use super::*;
use crate::ui_view_models::active_stage_label as active_stage_label_model;

pub(crate) fn active_stage_label(app: &ShellApp) -> Option<&'static str> {
    active_stage_label_model(app)
}

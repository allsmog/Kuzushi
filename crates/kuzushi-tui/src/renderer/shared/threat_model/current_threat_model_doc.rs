use super::*;

pub(crate) fn current_threat_model_doc(app: &ShellApp) -> Option<serde_json::Value> {
    crate::ui_view_models::threat_model_doc(app)
}

use super::*;

pub(crate) fn current_threat_model_doc(app: &ShellApp) -> Option<serde_json::Value> {
    let cwd = app
        .target
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let doc = kuzushi_core::load_persistent_threat_model(&cwd)?;
    if doc.is_null() {
        return None;
    }
    Some(doc)
}

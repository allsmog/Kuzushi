use crate::ShellApp;
use std::path::PathBuf;

pub(crate) fn threat_model_doc(app: &ShellApp) -> Option<serde_json::Value> {
    let doc = kuzushi_core::load_persistent_threat_model(&threat_model_root(app))?;
    if doc.is_null() {
        return None;
    }
    Some(doc)
}

fn threat_model_root(app: &ShellApp) -> PathBuf {
    app.target
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

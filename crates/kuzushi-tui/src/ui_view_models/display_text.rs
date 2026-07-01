use crate::ShellApp;
use kuzushi_core::NestedProjectKind;

pub(crate) fn compact_target_path(value: &str) -> String {
    let trimmed = value.trim_end_matches('/');
    let name = trimmed
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(trimmed);
    if name.is_empty() {
        "target:/".to_string()
    } else {
        format!("./{name}")
    }
}

pub(crate) fn active_project_scope_label(app: &ShellApp) -> Option<String> {
    let scope = app.active_scope.as_ref()?;
    (scope.kind != NestedProjectKind::Root).then(|| scope.rel_path.clone())
}

pub(crate) fn scoped_target_path_label(app: &ShellApp) -> String {
    let target = app
        .target
        .as_ref()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| "none".to_string());
    active_project_scope_label(app)
        .map(|scope| format!("{target} ▸ {scope}"))
        .unwrap_or(target)
}

pub(crate) fn format_session_cost(usd: f64) -> String {
    if usd < 0.01 {
        format!("${usd:.4}")
    } else if usd < 100.0 {
        format!("${usd:.2}")
    } else {
        format!("${usd:.0}")
    }
}

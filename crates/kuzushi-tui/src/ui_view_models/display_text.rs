use crate::ShellApp;
use kuzushi_core::NestedProjectKind;
use std::path::{Path, PathBuf};

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
    let scope = app.active_scope()?;
    (scope.kind != NestedProjectKind::Root).then(|| scope.rel_path.clone())
}

pub(crate) fn scoped_target_path_label(app: &ShellApp) -> String {
    let target = app
        .target()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| "none".to_string());
    active_project_scope_label(app)
        .map(|scope| format!("{target} › {scope}"))
        .unwrap_or(target)
}

pub(crate) fn workspace_artifact_path_label(app: &ShellApp, path: &Path) -> String {
    let relative = app
        .target()
        .and_then(|target| path.strip_prefix(target).ok().map(Path::to_path_buf))
        .or_else(|| kuzushi_state_suffix(path));
    relative
        .as_deref()
        .map(dot_relative_path)
        .unwrap_or_else(|| compact_target_path(&path.display().to_string()))
}

fn kuzushi_state_suffix(path: &Path) -> Option<PathBuf> {
    let mut suffix = PathBuf::new();
    let mut found = false;
    for component in path.components() {
        if found || component.as_os_str() == ".kuzushi" {
            found = true;
            suffix.push(component.as_os_str());
        }
    }
    found.then_some(suffix)
}

fn dot_relative_path(path: &Path) -> String {
    format!("./{}", path.display())
}

pub(crate) fn format_session_cost(usd: f64) -> String {
    if usd == 0.0 {
        "$0.00".to_string()
    } else if usd < 0.01 {
        format!("${usd:.4}")
    } else if usd < 100.0 {
        format!("${usd:.2}")
    } else {
        format!("${usd:.0}")
    }
}

pub(crate) fn format_runtime_cost(
    report: kuzushi_core::runtime::RuntimeCostReport,
    accounting_error: Option<&str>,
) -> String {
    if accounting_error.is_some() {
        return "cost invalid".to_string();
    }
    if report.is_unavailable() {
        return "cost unavailable".to_string();
    }
    let formatted = format_session_cost(report.observed_usd());
    if report.is_complete() {
        formatted
    } else {
        format!(">={formatted} (incomplete)")
    }
}

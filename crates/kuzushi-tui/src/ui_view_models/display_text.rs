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
        return "cost accounting error".to_string();
    }
    if report.is_unavailable() {
        return "cost not recorded".to_string();
    }
    let formatted = format_session_cost(report.observed_usd());
    if report.is_complete() {
        formatted
    } else {
        format!(">={formatted} (metering incomplete)")
    }
}

/// Local stores record some times (review decisions, export receipts) as
/// bare epoch seconds; render those as RFC 3339 UTC so an operator never
/// reads a raw integer as a time. Anything else is shown as recorded.
pub(crate) fn recorded_timestamp_label(recorded: &str) -> String {
    recorded
        .trim()
        .parse::<u64>()
        .map(kuzushi_core::session_transcript::utc_timestamp_from_unix_seconds)
        .unwrap_or_else(|_| recorded.to_string())
}

#[cfg(test)]
mod recorded_timestamp_tests {
    use super::recorded_timestamp_label;

    #[test]
    fn epoch_seconds_render_as_utc_and_other_values_as_recorded() {
        assert_eq!(
            recorded_timestamp_label("1790260983"),
            "2026-09-24T14:43:03Z"
        );
        assert_eq!(
            recorded_timestamp_label("2026-09-24T00:00:00Z"),
            "2026-09-24T00:00:00Z"
        );
    }
}

#[cfg(test)]
mod runtime_cost_tests {
    use super::*;
    use kuzushi_core::runtime::{RuntimeCost, RuntimeCostReport};

    #[test]
    fn compact_cost_preserves_unknown_spend_without_inferring_call_counts() {
        assert_eq!(
            format_runtime_cost(RuntimeCostReport::known(RuntimeCost::ZERO), None),
            "$0.00"
        );
        assert_eq!(
            format_runtime_cost(RuntimeCostReport::INCOMPLETE_ZERO, None),
            ">=$0.00 (metering incomplete)"
        );
        assert_eq!(
            format_runtime_cost(RuntimeCostReport::UNAVAILABLE, None),
            "cost not recorded"
        );
        assert_eq!(
            format_runtime_cost(
                RuntimeCostReport::known(RuntimeCost::ZERO),
                Some("overflow")
            ),
            "cost accounting error"
        );
    }
}

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
        fractional_cost_text(usd)
    } else if usd < 100.0 {
        format!("${usd:.2}")
    } else {
        format!("${usd:.0}")
    }
}

fn fractional_cost_text(usd: f64) -> String {
    if usd < 0.00005 {
        return format!("${usd:.2e}");
    }
    format!("${usd:.4}")
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
    recorded_cost_text(report)
}

/// Exact spend as-is, a labelled `~` estimate for unmetered calls, or a `>=`
/// lower bound when some unmetered spend has no estimate.
fn recorded_cost_text(report: kuzushi_core::runtime::RuntimeCostReport) -> String {
    if report.is_complete() {
        return format_session_cost(report.observed_usd());
    }
    match report.estimated_total_usd() {
        Some(total) => format!("~{} (estimated)", format_session_cost(total)),
        None => unmetered_cost_text(report.observed_usd()),
    }
}

fn unmetered_cost_text(observed: f64) -> String {
    if observed == 0.0 {
        return "unknown (metering incomplete)".to_string();
    }
    format!(">={} (metering incomplete)", format_session_cost(observed))
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
    fn positive_subtotals_remain_visible_without_claiming_the_unknown_total() {
        let subtotal = RuntimeCost::from_usd(0.000001, "owned receipt").unwrap();
        let label = format_runtime_cost(RuntimeCostReport::incomplete(subtotal), None);
        assert_eq!(label, ">=$1.00e-6 (metering incomplete)");
        assert!(!label.contains("$0.00"));
        assert_eq!(
            format_runtime_cost(RuntimeCostReport::known(subtotal), None),
            "$1.00e-6"
        );
    }

    #[test]
    fn estimates_remain_qualified_even_when_the_observed_subtotal_is_zero() {
        let report = RuntimeCostReport::INCOMPLETE_ZERO
            .with_unmetered_estimate(Some(RuntimeCost::from_usd(0.25, "owned estimate").unwrap()));
        assert_eq!(format_runtime_cost(report, None), "~$0.25 (estimated)");
    }

    #[test]
    fn compact_cost_preserves_unknown_spend_without_inferring_call_counts() {
        assert_eq!(
            format_runtime_cost(RuntimeCostReport::known(RuntimeCost::ZERO), None),
            "$0.00"
        );
        assert_eq!(
            format_runtime_cost(RuntimeCostReport::INCOMPLETE_ZERO, None),
            "unknown (metering incomplete)"
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

/// Quoting distinguishes literal edge spaces without changing the stored path.
/// `src/a.py` and ` src/a.py` are different files, and the space is invisible
/// on screen, so an unquoted path lets an operator read one as the other.
pub(crate) fn display_path(path: &str) -> String {
    if path.trim() == path {
        return path.to_string();
    }
    serde_json::to_string(path).expect("a path string is serializable")
}

/// Display form of a recorded finding location (`path:line`, `path:start-end`).
/// The path is quoted when its edge whitespace would otherwise be invisible;
/// the recorded line stays outside the quotes so the location still reads as
/// one.
pub(crate) fn display_location(location: &str) -> String {
    let (path, line) = split_recorded_line(location);
    if path.trim() == path {
        return location.to_string();
    }
    format!("{}{line}", display_path(path))
}

/// Split the trailing `:line` or `:start-end` that `finding_location` records
/// from the path before it. A location carrying neither is all path.
fn split_recorded_line(location: &str) -> (&str, &str) {
    let Some(colon) = location.rfind(':') else {
        return (location, "");
    };
    let (path, line) = location.split_at(colon);
    if recorded_line(&line[1..]) {
        return (path, line);
    }
    (location, "")
}

fn recorded_line(line: &str) -> bool {
    match line.split_once('-') {
        Some((start, end)) => line_number(start) && line_number(end),
        None => line_number(line),
    }
}

fn line_number(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod literal_path_tests {
    use super::*;

    #[test]
    fn literal_path_display_distinguishes_edge_spaces_from_other_members() {
        assert_eq!(display_path("app"), "app");
        assert_eq!(display_path(" app "), "\" app \"");
        assert_eq!(display_path(" app /lib.py"), "\" app /lib.py\"");
        assert_eq!(display_path("app/a b.py"), "app/a b.py");
        assert_eq!(display_path(" app\" "), "\" app\\\" \"");
    }

    #[test]
    fn location_display_quotes_the_path_and_keeps_the_recorded_line_outside() {
        assert_eq!(display_location("src/a.py:12"), "src/a.py:12");
        assert_eq!(display_location(" src/a.py:12"), "\" src/a.py\":12");
        assert_eq!(display_location(" src/a.py:12-18"), "\" src/a.py\":12-18");
        assert_eq!(display_location(" src/a:b.py:12"), "\" src/a:b.py\":12");
    }

    #[test]
    fn a_location_without_a_recorded_line_is_quoted_as_a_whole_path() {
        assert_eq!(display_location(" src/a.py "), "\" src/a.py \"");
        assert_eq!(display_location(" src/log:latest"), "\" src/log:latest\"");
        assert_eq!(display_location(" src/a.py:12-"), "\" src/a.py:12-\"");
    }
}

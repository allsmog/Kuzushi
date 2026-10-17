use crate::{app::ViewDataState, ShellApp};
use kuzushi_core::{
    allowance::RunAllowanceContext,
    run_artifacts::{RecordedAllowanceOrigin, RecordedRequestScope, RunRequestContext},
    run_lifecycle::SafeText,
};

pub(crate) struct RequestContextModel {
    scope: String,
    calls: String,
    pub(crate) details: Vec<String>,
    pub(crate) rail: Vec<String>,
}

impl RequestContextModel {
    pub(crate) fn compact(&self, width: usize) -> String {
        let suffix = format!(" · {}", self.calls);
        if width < 9 + unicode_width::UnicodeWidthStr::width(self.calls.as_str()) {
            return fit(&self.calls, width);
        }
        let space =
            width.saturating_sub(6 + unicode_width::UnicodeWidthStr::width(suffix.as_str()));
        let scope = fit(&self.scope, space);
        fit(&format!("Scope {scope}{suffix}"), width)
    }
}

pub(crate) fn replay_request_context(app: &ShellApp, run_id: &str) -> RequestContextModel {
    let Some(target) = app.target() else {
        return unavailable("Select a target to read recorded request context.");
    };
    let cache = app.workbench_cache();
    let state = cache.borrow().cached_run_request_context(target, run_id);
    match state {
        ViewDataState::Ready(Ok(context)) => present(&context),
        ViewDataState::Ready(Err(error)) => unavailable(&error),
        _ => RequestContextModel {
            scope: "loading".into(),
            calls: "limits loading".into(),
            details: vec!["Recorded request and investigation limits are loading.".into()],
            rail: vec!["Request / limits loading".into()],
        },
    }
}

fn unavailable(error: &str) -> RequestContextModel {
    RequestContextModel {
        scope: "unavailable".into(),
        calls: "limits unavailable".into(),
        details: vec![
            safe(format!("Recorded request unavailable: {error}")),
            "r refreshes this read without starting work.".into(),
        ],
        rail: vec![
            "Request / limits unavailable".into(),
            "r refreshes the read".into(),
        ],
    }
}

fn present(context: &RunRequestContext) -> RequestContextModel {
    let (scope, mut details) = scope_rows(&context.scope);
    let (calls, allowance) = allowance_rows(&context.allowance, &context.allowance_origin);
    details.extend(allowance);
    details.push(format!(
        "Read at {}. r refreshes without starting work.",
        kuzushi_core::session_transcript::utc_timestamp_from_unix_seconds(context.read_at_unix)
    ));
    details.push(
        "Requested membership does not establish discovery coverage or authorize more work.".into(),
    );
    let mut rail = vec![format!("Scope {scope}")];
    rail.extend(allowance_rail(
        &context.allowance,
        &context.allowance_origin,
    ));
    RequestContextModel {
        scope,
        calls,
        details,
        rail,
    }
}

fn scope_rows(scope: &Result<RecordedRequestScope, String>) -> (String, Vec<String>) {
    match scope {
        Ok(RecordedRequestScope::Accepted { name, reference }) => (
            safe(name),
            vec![safe(format!(
                "Requested scope: {name} ({}, proposal {} r{})",
                reference.scope_id, reference.proposal.proposal_id, reference.proposal.revision
            ))],
        ),
        Ok(RecordedRequestScope::ExplicitPaths { count }) => explicit_path_rows(*count),
        Ok(RecordedRequestScope::NotRecorded) => (
            "not recorded".into(),
            vec!["Requested scope membership is not recorded.".into()],
        ),
        Err(error) => (
            "unavailable".into(),
            vec![safe(format!("Requested scope unavailable: {error}"))],
        ),
    }
}

fn explicit_path_rows(count: usize) -> (String, Vec<String>) {
    let unit = if count == 1 { "path" } else { "paths" };
    (
        format!("{count} {unit}"),
        vec![format!(
            "Requested selection: {count} explicit {unit}; no accepted scope reference."
        )],
    )
}

fn allowance_rows(
    allowance: &Result<Option<RunAllowanceContext>, String>,
    origin: &RecordedAllowanceOrigin,
) -> (String, Vec<String>) {
    match allowance {
        Ok(Some(context)) => recorded_allowance(context, origin),
        Ok(None) => (
            "no recorded grant".into(),
            vec!["No investigation allowance reference recorded for this run.".into()],
        ),
        Err(error) => (
            "limits unavailable".into(),
            vec![safe(format!("Investigation limits unavailable: {error}"))],
        ),
    }
}

fn recorded_allowance(
    context: &RunAllowanceContext,
    origin: &RecordedAllowanceOrigin,
) -> (String, Vec<String>) {
    let current = &context.current;
    let mut calls = format!(
        "calls {}/{} at read",
        current.committed_calls, current.limits.max_provider_calls
    );
    if let RecordedAllowanceOrigin::Inherited { work, .. } = origin {
        calls = format!("inherited {work:?} · {calls}");
    }
    let label = grant_label(origin);
    let mut rows = vec![safe(format!(
        "{label}: {} r{}; {} total, {} protected Review; {}",
        context.reference.investigation_id,
        context.reference.revision,
        call_quantity(context.approved_limits.max_provider_calls),
        context.approved_limits.protected_review_calls,
        context.approved_model
    ))];
    rows.extend(accounting_rows(context, origin));
    rows.extend(latest_ledger_rows(current));
    (calls, rows)
}

fn grant_label(origin: &RecordedAllowanceOrigin) -> String {
    match origin {
        RecordedAllowanceOrigin::Inherited { work, .. } => format!("Inherited {work:?} grant"),
        _ => "Run grant".into(),
    }
}

fn call_quantity(count: u32) -> String {
    let unit = if count == 1 { "call" } else { "calls" };
    format!("{count} {unit}")
}

fn accounting_rows(context: &RunAllowanceContext, origin: &RecordedAllowanceOrigin) -> Vec<String> {
    let calls = format!(
        "{} committed calls; {} unsettled.",
        context.run_committed_calls, context.run_unsettled_calls
    );
    match origin {
        RecordedAllowanceOrigin::Inherited {
            accounting_run_id, ..
        } => vec![
            safe(format!("Accounting run: {accounting_run_id}; {calls}")),
            "These are accounting-run totals, not isolated child charges.".into(),
            "Reading an inherited grant does not approve or start child work.".into(),
        ],
        _ => vec![format!("This run: {calls}")],
    }
}

fn latest_ledger_rows(current: &kuzushi_core::allowance::AllowanceSnapshot) -> Vec<String> {
    vec![
        safe(format!(
            "Latest ledger at read: r{}; {}/{} calls committed; {}",
            current.revision,
            current.committed_calls,
            current.limits.max_provider_calls,
            current.model
        )),
        format!(
            "Remaining at read: {} other calls; {} protected Review; {} unsettled overall.",
            current.non_review_remaining(),
            current.protected_review_remaining(),
            current.unresolved_calls
        ),
        format!(
            "Investigation cost: {}",
            kuzushi_core::run_lifecycle::cost_label(current.cost)
        ),
    ]
}

fn allowance_rail(
    allowance: &Result<Option<RunAllowanceContext>, String>,
    origin: &RecordedAllowanceOrigin,
) -> Vec<String> {
    let Ok(Some(context)) = allowance else {
        return vec![
            allowance_rows(allowance, origin).0,
            "r refreshes the read".into(),
        ];
    };
    let current = &context.current;
    vec![
        format!(
            "{} r{}: {}",
            grant_label(origin),
            context.reference.revision,
            call_quantity(context.approved_limits.max_provider_calls)
        ),
        format!(
            "At read r{}: {}/{} calls",
            current.revision, current.committed_calls, current.limits.max_provider_calls
        ),
        format!("{} Review protected", current.protected_review_remaining()),
        format!("{} unsettled overall", current.unresolved_calls),
        kuzushi_core::run_lifecycle::cost_label(current.cost),
        "r refreshes the read".into(),
    ]
}

fn fit(text: &str, width: usize) -> String {
    use unicode_width::UnicodeWidthStr;
    if text.width() <= width {
        return text.into();
    }
    if width == 0 {
        return String::new();
    }
    format!("{}…", fitted_prefix(text, width - 1))
}

fn fitted_prefix(text: &str, width: usize) -> String {
    use unicode_segmentation::UnicodeSegmentation;
    use unicode_width::UnicodeWidthStr;
    let mut head = String::new();
    for part in text.graphemes(true) {
        if head.width() + part.width() > width {
            break;
        }
        head.push_str(part);
    }
    head
}

fn safe(text: impl AsRef<str>) -> String {
    SafeText::condensed_line(text).to_string()
}

#[cfg(test)]
mod tests;

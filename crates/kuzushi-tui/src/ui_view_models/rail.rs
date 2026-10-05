use crate::app::AttentionBroker;
use crate::theme;
use crate::ShellApp;
use ratatui::prelude::{Line, Span};

/// One context-rail section: a heading plus its rows. A section that would be
/// empty is simply not built — the rail grows into the session instead of
/// opening as a wall of zeros.
pub(crate) struct RailSection {
    pub(crate) title: &'static str,
    pub(crate) rows: Vec<Line<'static>>,
}

/// Sections in salience order: identity → needs-you → journey → in-flight →
/// evidence → money. Fixed-height sections sit at the top, unbounded ones at
/// the bottom, so growth never pushes the stable facts off-screen.
pub(crate) fn rail_sections(app: &ShellApp, width: usize) -> Vec<RailSection> {
    [
        Some(engagement_section(app, width)),
        attention_section(app, width),
        journey_section(app),
        in_flight_section(app, width),
        findings_section(app, width),
        cost_section_unless_shown(app),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Run Focus already reports cost in its header, so the rail does not repeat it.
fn cost_section_unless_shown(app: &ShellApp) -> Option<RailSection> {
    (app.shell_view() != crate::ShellView::Activity).then(|| cost_section(app))
}

/// Always present: which target, which scope. The rail's anchor row.
fn engagement_section(app: &ShellApp, width: usize) -> RailSection {
    let target = app
        .target()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "no target".to_string());
    let mut rows = vec![Line::styled(
        truncate_left(&target, width),
        theme::primary(),
    )];
    if let Some(chip) = super::screen_context_model(app).scope_chip() {
        rows.push(muted_row(&chip, width));
    }
    RailSection {
        title: "ENGAGEMENT",
        rows,
    }
}

/// Every attention item, not the footer's collapsed single segment. Hidden
/// when nothing needs the operator.
fn attention_section(app: &ShellApp, width: usize) -> Option<RailSection> {
    let broker = AttentionBroker::from_app(app);
    if broker.items().is_empty() {
        return None;
    }
    let rows = broker
        .items()
        .iter()
        .map(|item| {
            let text = truncate_right(
                &format!("{} · {}", item.kind.title(), item.route.hint()),
                width,
            );
            Line::styled(text, theme::warn())
        })
        .collect();
    Some(RailSection {
        title: "ATTENTION",
        rows,
    })
}

/// Phase chip + autonomy chip. Both are target-gated already, so the section
/// hides itself until an engagement commits.
fn journey_section(app: &ShellApp) -> Option<RailSection> {
    let rows: Vec<Line<'static>> = [
        super::journey_footer_segment(app),
        super::autonomy_footer_segment(app),
    ]
    .into_iter()
    .flatten()
    .map(|segment| Line::styled(segment, theme::muted()))
    .collect();
    (!rows.is_empty()).then_some(RailSection {
        title: "JOURNEY",
        rows,
    })
}

/// Self-erasing: running tool plus queued work, gone once everything settles.
fn in_flight_section(app: &ShellApp, width: usize) -> Option<RailSection> {
    let mut rows = Vec::new();
    if let Some(tool) = app.running_tool_name_owned() {
        rows.push(Line::from(vec![
            Span::styled(format!("{} ", app.spinner_glyph()), theme::accent()),
            Span::styled(
                truncate_right(&tool, width.saturating_sub(2)),
                theme::muted(),
            ),
        ]));
    }
    let planned = app.engagement.pending_planning_step_count();
    if planned > 0 {
        rows.push(muted_row(&format!("{planned} planned"), width));
    }
    let steered = app.steer_queue().len();
    if steered > 0 {
        rows.push(muted_row(&format!("{steered} steered"), width));
    }
    (!rows.is_empty()).then_some(RailSection {
        title: "IN FLIGHT",
        rows,
    })
}

/// Unfiltered ledger truth: severity mix plus review/proof progress. Hidden
/// while the ledger is empty — a clean target needs no findings chrome.
fn findings_section(app: &ShellApp, width: usize) -> Option<RailSection> {
    let total = app.findings_total_count();
    if total == 0 {
        return None;
    }
    let summary = super::compact_status_footer_findings_summary_with_total(app.findings(), total);
    let mut rows = vec![muted_row(&summary, width)];
    if let Some(counts) = app.domain().finding_ledger_counts() {
        rows.push(muted_row(
            &format!(
                "{}/{} reviewed · {} confirmed",
                counts.reviewed, counts.total, counts.confirmed
            ),
            width,
        ));
    }
    Some(RailSection {
        title: "FINDINGS",
        rows,
    })
}

/// Always present: spend is monotonically worsening and always relevant.
/// Spend is rendered through the shared runtime-cost formatter, so a session
/// whose calls were not metered (subscription/OAuth models report no price)
/// never reads as a measured `$0.00`, and a budget share over incomplete
/// metering is labelled a lower bound.
fn cost_section(app: &ShellApp) -> RailSection {
    let session = app.session();
    let rows = match session.session_budget_usd() {
        Some(budget) if budget > 0.0 => budget_rows(budget_spend(app), budget),
        _ => vec![
            Line::styled(unbudgeted_spend_label(app), theme::muted()),
            Line::styled("budget not enforced".to_string(), theme::subtle()),
        ],
    };
    RailSection {
        title: "SESSION COST",
        rows,
    }
}

/// A metered session reads `$X spent`; anything else keeps the shared
/// formatter's own qualifier (`>=$X (metering incomplete)`, `cost not
/// recorded`, `cost accounting error`) instead of a bare measured amount.
fn unbudgeted_spend_label(app: &ShellApp) -> String {
    let session = app.session();
    let spent = super::format_runtime_cost(
        session.session_cost_report(),
        session.cost_accounting_error(),
    );
    if session.session_cost_report().is_complete() && session.cost_accounting_error().is_none() {
        return format!("{spent} spent");
    }
    spent
}

/// How firmly the rail may state spend against a budget.
enum BudgetSpend {
    Metered(f64),
    Estimated(f64),
    LowerBound(f64),
}

fn budget_spend(app: &ShellApp) -> BudgetSpend {
    let session = app.session();
    let report = session.session_cost_report();
    match session.budget_spend_usd() {
        Some(spent) if report.is_estimated() => BudgetSpend::Estimated(spent),
        Some(spent) => BudgetSpend::Metered(spent),
        None => BudgetSpend::LowerBound(report.observed_usd()),
    }
}

impl BudgetSpend {
    fn bound_and_usd(&self) -> (&'static str, f64) {
        match *self {
            Self::Metered(usd) => ("", usd),
            Self::Estimated(usd) => ("~", usd),
            Self::LowerBound(usd) => (">=", usd),
        }
    }

    fn share(&self, percent: u64) -> String {
        match self {
            Self::Metered(_) => format!("{percent}% of budget"),
            Self::Estimated(_) => format!("~{percent}% · estimated"),
            Self::LowerBound(_) => format!(">={percent}% · calls unmetered"),
        }
    }
}

fn budget_rows(spend: BudgetSpend, budget: f64) -> Vec<Line<'static>> {
    let (bound, observed) = spend.bound_and_usd();
    let percent = ((observed / budget) * 100.0).round() as u64;
    let share = spend.share(percent);
    let style = if percent >= 80 {
        theme::warn()
    } else {
        theme::muted()
    };
    vec![
        Line::styled(
            format!("{bound}${observed:.2} of ${budget:.2}"),
            theme::muted(),
        ),
        Line::styled(share, style),
    ]
}

fn muted_row(text: &str, width: usize) -> Line<'static> {
    Line::styled(truncate_right(text, width), theme::muted())
}

fn truncate_right(value: &str, width: usize) -> String {
    let chars = value.chars().count();
    if chars <= width || width < 2 {
        return value.to_string();
    }
    let head: String = value.chars().take(width - 1).collect();
    format!("{head}…")
}

/// Keep the tail of `value` when it overflows: for paths and target names the
/// leaf segment is the identifying part, so drop the front, not the back.
fn truncate_left(value: &str, width: usize) -> String {
    let chars = value.chars().count();
    if chars <= width || width < 2 {
        return value.to_string();
    }
    let tail: String = value.chars().skip(chars - (width - 1)).collect();
    format!("…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    fn section_titles(app: &ShellApp) -> Vec<&'static str> {
        rail_sections(app, 33)
            .iter()
            .map(|section| section.title)
            .collect()
    }

    #[test]
    fn idle_targetless_rail_carries_only_identity_and_cost() {
        let app = ShellApp::new(V2Config::default(), None);

        assert_eq!(section_titles(&app), vec!["ENGAGEMENT", "SESSION COST"]);
    }

    #[test]
    fn targetless_engagement_names_the_absence() {
        let app = ShellApp::new(V2Config::default(), None);
        let sections = rail_sections(&app, 33);

        assert_eq!(sections[0].rows[0].to_string(), "no target");
    }

    #[test]
    fn unset_budget_reads_not_enforced() {
        let app = ShellApp::new(V2Config::default(), None);
        let sections = rail_sections(&app, 33);
        let cost = sections.last().unwrap();

        assert_eq!(cost.rows[0].to_string(), "$0.00 spent");
        assert_eq!(cost.rows[1].to_string(), "budget not enforced");
    }

    #[test]
    fn unmetered_spend_never_reads_as_a_measured_zero() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.session_mut().set_session_cost_report_for_test(
            kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
        );
        let sections = rail_sections(&app, 40);
        let cost = sections.last().unwrap();

        assert_eq!(cost.rows[0].to_string(), ">=$0.00 (metering incomplete)");
    }

    #[test]
    fn a_budget_share_over_unmetered_calls_is_a_lower_bound() {
        let unmetered = budget_rows(BudgetSpend::LowerBound(1.0), 10.0);
        assert_eq!(unmetered[0].to_string(), ">=$1.00 of $10.00");
        assert_eq!(unmetered[1].to_string(), ">=10% · calls unmetered");
        let metered = budget_rows(BudgetSpend::Metered(1.0), 10.0);
        assert_eq!(metered[0].to_string(), "$1.00 of $10.00");
        assert_eq!(metered[1].to_string(), "10% of budget");
        let estimated = budget_rows(BudgetSpend::Estimated(1.0), 10.0);
        assert_eq!(estimated[0].to_string(), "~$1.00 of $10.00");
        assert_eq!(estimated[1].to_string(), "~10% · estimated");
    }

    #[test]
    fn an_estimated_session_is_labelled_and_enforces_its_budget() {
        use kuzushi_core::runtime::{RuntimeCost, RuntimeCostReport};
        let estimate = RuntimeCost::from_usd(0.5, "cost").unwrap();
        let report = RuntimeCostReport::INCOMPLETE_ZERO.with_unmetered_estimate(Some(estimate));
        assert_eq!(
            crate::ui_view_models::format_runtime_cost(report, None),
            "~$0.50 (estimated)"
        );
        assert_eq!(
            crate::ui_view_models::format_runtime_cost(RuntimeCostReport::INCOMPLETE_ZERO, None),
            ">=$0.00 (metering incomplete)"
        );
    }

    #[test]
    fn attention_section_surfaces_pending_approval() {
        use crate::app::{ConfirmKind, PendingConfirm};
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory_mut().pending_confirm = Some(PendingConfirm {
            kind: ConfirmKind::NetworkEgress,
            tool: "scanner:run".to_string(),
            target: "example.test".to_string(),
            rationale: None,
            allowlist: None,
            actor: None,
            remembered: false,
        });

        let sections = rail_sections(&app, 33);
        let attention = sections
            .iter()
            .find(|section| section.title == "ATTENTION")
            .expect("attention section");

        assert_eq!(attention.rows[0].to_string(), "APPROVAL REQUIRED · confirm");
    }

    #[test]
    fn in_flight_section_self_erases_when_idle() {
        let app = ShellApp::new(V2Config::default(), None);

        assert!(!section_titles(&app).contains(&"IN FLIGHT"));
    }

    #[test]
    fn truncate_right_and_left_respect_width() {
        assert_eq!(truncate_right("abcdefg", 6), "abcde…");
        assert_eq!(truncate_left("abcdefg", 6), "…cdefg");
        assert_eq!(truncate_right("abc", 6), "abc");
    }
}

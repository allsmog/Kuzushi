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
        Some(cost_section(app)),
    ]
    .into_iter()
    .flatten()
    .collect()
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
                "{}/{} reviewed · {} proven",
                counts.reviewed, counts.total, counts.proven
            ),
            width,
        ));
        if counts.remediated > 0 {
            rows.push(muted_row(
                &format!("{} remediated", counts.remediated),
                width,
            ));
        }
    }
    Some(RailSection {
        title: "FINDINGS",
        rows,
    })
}

/// Always present: spend is monotonically worsening and always relevant.
fn cost_section(app: &ShellApp) -> RailSection {
    let spent = app.session().session_cost_usd();
    let rows = match app.session().session_budget_usd() {
        Some(budget) if budget > 0.0 => {
            let percent = ((spent / budget) * 100.0).round() as u64;
            vec![
                Line::styled(format!("${spent:.2} of ${budget:.2}"), theme::muted()),
                Line::styled(
                    format!("{percent}% of budget"),
                    if percent >= 80 {
                        theme::warn()
                    } else {
                        theme::muted()
                    },
                ),
            ]
        }
        _ => vec![
            Line::styled(format!("${spent:.2} spent"), theme::muted()),
            Line::styled("budget not enforced".to_string(), theme::subtle()),
        ],
    };
    RailSection {
        title: "COST",
        rows,
    }
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

        assert_eq!(section_titles(&app), vec!["ENGAGEMENT", "COST"]);
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

use super::batch_occurrence_lines::append_batch_occurrence;
use super::batch_scan_config_lines::append_batch_scan_config;
use super::*;
use crate::app::CampaignRouteState;
use crate::ui_view_models::campaign_job_scope_label as job_scope_label;
use kuzushi_core::capabilities::campaign::snapshot::{CampaignJobSnapshot, CampaignSnapshot};

const CAMPAIGN_LIST_WIDTHS: [usize; 4] = [18, 14, 6, 30];
const JOB_LIST_WIDTHS: [usize; 7] = [4, 22, 10, 4, 5, 12, 5];

#[cfg(test)]
mod history_tests;

/// The Campaign deck: list mode is one row per planned campaign; detail mode
/// is the selected campaign's ranked job matrix with include/exclude marks.
/// All lifecycle truth comes from the snapshot fold (plan + dispatcher queue).
pub(crate) fn campaign_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let deck = app.router.campaign();
    let mut lines = context_strip(app, area);
    lines.push(blank());
    if append_study_surfaces(&mut lines, app, area) {
        return lines;
    }
    append_history_coverage(&mut lines, deck, area.width);
    if deck.has_dispatcher_failure_notice() {
        let context = lines;
        lines = Vec::new();
        append_campaign_notice(&mut lines, deck, area);
        lines.extend(context);
    }
    match deck.selected_campaign().filter(|_| deck.detail) {
        Some(campaign) => append_campaign_detail(&mut lines, deck, campaign, area),
        None => append_campaign_list(&mut lines, deck, area),
    }
    append_deck_footer(&mut lines, deck, area, app.study_navigation_return_active());
    lines
}

fn append_study_surfaces(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) -> bool {
    if let Some(matrix) = crate::ui_view_models::matrix_plain_lines(app, area.width as usize) {
        lines.extend(matrix.into_iter().map(Line::from));
        return true;
    }
    if app.context_generation().is_some() {
        lines.extend(
            crate::ui_view_models::context_generation::generation_lines(app, area.width as usize)
                .into_iter()
                .map(|text| Line::styled(text, theme::primary())),
        );
        return true;
    }
    if append_study_picker(lines, app, area) {
        return true;
    }
    append_study_form(lines, app, area)
}

fn append_study_form(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) -> bool {
    let Some(config) = crate::ui_view_models::study_config::study_projection(app) else {
        return false;
    };
    append_batch_scan_config(lines, &config, area);
    true
}

fn append_study_picker(lines: &mut Vec<Line<'static>>, app: &ShellApp, area: Rect) -> bool {
    if let Some(document) = crate::ui_view_models::study_resource_picker::resource_picker_document(
        app,
        area.width as usize,
    ) {
        lines.push(divider("HISTORICAL USAGE", area.width));
        lines.extend(document.into_iter().map(Line::from));
        lines.push(Line::from("↑↓ Enter · PgUp/Dn · r refresh · Esc back"));
        return true;
    }
    if app.study_engine_picker().is_some() {
        super::batch_scan_config_lines::append_study_engines(lines, app, area);
        return true;
    }
    if app.study_context_picker().is_some() {
        super::batch_scan_config_lines::append_study_context(lines, app, area);
        return true;
    }
    super::batch_scan_config_lines::append_scope_context(lines, app, area)
}

fn append_campaign_list(lines: &mut Vec<Line<'static>>, deck: &CampaignRouteState, area: Rect) {
    lines.push(divider("CAMPAIGNS", area.width));
    append_campaign_trend(lines, deck, area.width as usize);
    if deck.campaigns.is_empty() {
        append_history_empty_state(lines, deck);
        return;
    }
    let widths = campaign_list_widths(area);
    lines.push(aligned_header(
        &["  ", "campaign", "tool", "jobs", "states"],
        &widths,
    ));
    for (index, campaign) in deck.campaigns.iter().enumerate() {
        lines.push(campaign_row_line(
            campaign,
            index == deck.selected_campaign,
            &widths,
        ));
    }
}

fn append_history_coverage(lines: &mut Vec<Line<'static>>, deck: &CampaignRouteState, width: u16) {
    let warning = deck
        .history_coverage
        .as_ref()
        .and_then(|coverage| coverage.limitation_label());
    if let Some(warning) = warning {
        lines.extend(
            wrap_text(&warning, usize::from(width).max(1))
                .into_iter()
                .map(|text| Line::styled(text, theme::warn())),
        );
    }
}

fn append_history_empty_state(lines: &mut Vec<Line<'static>>, deck: &CampaignRouteState) {
    if deck
        .history_coverage
        .as_ref()
        .is_some_and(|coverage| !coverage.complete())
    {
        lines.push(Line::from(
            "No readable investigations in this view. r refresh or open an exact campaign ID.",
        ));
        return;
    }
    append_empty_deck(lines);
}

fn append_campaign_trend(lines: &mut Vec<Line<'static>>, deck: &CampaignRouteState, width: usize) {
    if let Some(trend) = &deck.trend {
        append_workspace_trend(lines, &trend.strip_label(), width);
        if let Some(history) =
            kuzushi_core::capabilities::campaign::trend_history::history_reading_lines(
                &deck.trend_history,
            )
        {
            for part in history {
                push_deck_text(lines, &part, width, theme::subtle());
            }
        }
        lines.push(blank());
    }
}

fn append_workspace_trend(lines: &mut Vec<Line<'static>>, label: &str, width: usize) {
    if width >= 80 {
        push_deck_text(lines, label, width, theme::primary());
        return;
    }
    for part in label.split(" · ") {
        push_deck_text(lines, part, width, theme::primary());
    }
}

fn campaign_list_widths(area: Rect) -> [usize; 5] {
    let [id, tool, jobs, states] = CAMPAIGN_LIST_WIDTHS;
    fit_table_widths(
        area.width as usize,
        [2, id, tool, jobs, states],
        [1, 6, 4, 2, 7],
    )
}

fn campaign_row_line(
    campaign: &CampaignSnapshot,
    selected: bool,
    widths: &[usize; 5],
) -> Line<'static> {
    let marker = if selected { "▸" } else { " " };
    Line::from(vec![
        Span::styled(format!("{}  ", pad(marker, widths[0])), theme::accent()),
        Span::styled(
            format!(
                "{}  ",
                pad(&fit(&campaign_display_id(campaign), widths[1]), widths[1])
            ),
            theme::accent(),
        ),
        Span::styled(
            format!(
                "{}  ",
                pad(
                    &fit(campaign.tool.as_deref().unwrap_or("—"), widths[2]),
                    widths[2]
                )
            ),
            theme::subtle(),
        ),
        Span::styled(
            format!("{}  ", pad(&campaign.jobs.len().to_string(), widths[3])),
            theme::primary(),
        ),
        Span::styled(
            pad(&fit(&states_label(campaign), widths[4]), widths[4]),
            theme::primary(),
        ),
    ])
}

fn campaign_display_id(campaign: &CampaignSnapshot) -> String {
    if crate::app::is_scan_batch_snapshot(campaign) {
        return format!("[BATCH] {}", campaign.campaign_id);
    }
    campaign.campaign_id.clone()
}

pub(super) fn states_label(campaign: &CampaignSnapshot) -> String {
    let counts = campaign.state_counts();
    if counts.is_empty() {
        return "no jobs".to_string();
    }
    counts
        .iter()
        .map(|(state, count)| format!("{count} {state}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn append_campaign_detail(
    lines: &mut Vec<Line<'static>>,
    deck: &CampaignRouteState,
    campaign: &CampaignSnapshot,
    area: Rect,
) {
    if deck.job_detail {
        if let Some(job) = campaign.jobs.get(deck.selected_job) {
            super::fixed_jobs::append_selected_detail(lines, job, area.width as usize);
        }
        return;
    }
    super::summary::append_campaign_summary(lines, deck, campaign, area.width as usize);
    lines.push(blank());
    append_campaign_jobs(lines, deck, campaign, area);
    append_observations_hint(lines, campaign, area);
    if let Some(report) = deck
        .active_batch_report()
        .filter(|report| report.batch_id == campaign.campaign_id)
    {
        append_batch_occurrence(lines, report, area);
    }
}

fn append_observations_hint(
    lines: &mut Vec<Line<'static>>,
    campaign: &CampaignSnapshot,
    area: Rect,
) {
    if crate::app::is_scan_batch_snapshot(campaign) {
        push_deck_text(
            lines,
            "o observations · scopes Review to this batch · batch clear restores history",
            area.width as usize,
            theme::muted(),
        );
    }
}

fn append_campaign_jobs(
    lines: &mut Vec<Line<'static>>,
    deck: &CampaignRouteState,
    campaign: &CampaignSnapshot,
    area: Rect,
) {
    if campaign.kind.as_deref() == Some("context-study") {
        super::context_study_lines::append_context_jobs(lines, deck, campaign, area.width as usize);
        return;
    }
    if crate::app::is_fixed_study_snapshot(campaign) {
        super::fixed_jobs::append_fixed_jobs(lines, deck, campaign, area.width as usize);
        return;
    }
    let widths = job_list_widths(area);
    let compact = compact_job_table(deck, &widths);
    lines.push(job_table_header(compact, &widths));
    for (index, job) in campaign.jobs.iter().enumerate() {
        lines.push(job_row_line(
            deck,
            job,
            index == deck.selected_job,
            &widths,
            compact,
        ));
    }
    append_attempt_count_hint(lines, campaign, area.width as usize);
}

pub(super) fn append_attempt_count_hint(
    lines: &mut Vec<Line<'static>>,
    campaign: &CampaignSnapshot,
    width: usize,
) {
    if campaign.jobs.iter().any(|job| job.dispatches.is_none()) {
        push_deck_text(lines, "Lifetime totals unavailable for legacy rows. Current counts reset on resume; ? marks current counts in tables.", width, theme::muted());
    }
}

fn job_table_header(compact: bool, widths: &[usize; 9]) -> Line<'static> {
    if compact {
        return Line::styled("  job · state · attempt", theme::muted());
    }
    aligned_header(
        &[
            "  ",
            "in",
            "job",
            "state",
            "att",
            "prio",
            "cost",
            "find",
            "scope / threat",
        ],
        widths,
    )
}

fn job_list_widths(area: Rect) -> [usize; 9] {
    let [marker, job, state, attempts, priority, cost, findings] = JOB_LIST_WIDTHS;
    fit_table_widths(
        area.width as usize,
        [
            2, marker, job, state, attempts, priority, cost, findings, 36,
        ],
        [1, 1, 4, 3, 1, 1, 2, 1, 4],
    )
}

fn job_row_line(
    deck: &CampaignRouteState,
    job: &CampaignJobSnapshot,
    selected: bool,
    widths: &[usize; 9],
    compact: bool,
) -> Line<'static> {
    if compact {
        return compact_job_row(deck, job, selected, widths.iter().sum::<usize>() + 16);
    }
    let marker = if selected { "▸" } else { " " };
    let included = if deck.excluded.contains(&job.job_id) {
        "—"
    } else {
        "✓"
    };
    Line::from(job_row_spans(job, marker, included, widths))
}

fn compact_job_table(deck: &CampaignRouteState, widths: &[usize; 9]) -> bool {
    let widest_job = deck
        .selected_campaign()
        .into_iter()
        .flat_map(|campaign| campaign.jobs.iter())
        .map(|job| display_width(&job.job_id))
        .max()
        .unwrap_or(JOB_LIST_WIDTHS[1]);
    widths[2] < widest_job.max(JOB_LIST_WIDTHS[1]) || widths[3] < 10
}

fn compact_job_row(
    deck: &CampaignRouteState,
    job: &CampaignJobSnapshot,
    selected: bool,
    width: usize,
) -> Line<'static> {
    let marker = if selected { "▸" } else { " " };
    let included = if deck.excluded.contains(&job.job_id) {
        "×"
    } else {
        "✓"
    };
    let name = pad(
        &fit(&job.job_id, width.saturating_sub(19).max(1)),
        width.saturating_sub(19).max(1),
    );
    let text = format!(
        "{marker} {included} {name} {} a{}",
        fit(&job.state, 10),
        crate::ui_view_models::campaign_job_attempt_cell(job)
    );
    Line::styled(fit(&text, width), job_state_style(&job.state))
}

fn job_row_spans(
    job: &CampaignJobSnapshot,
    marker: &str,
    included: &str,
    widths: &[usize; 9],
) -> Vec<Span<'static>> {
    let findings_style = if job.findings.unwrap_or(0) > 0 {
        theme::warn()
    } else {
        theme::subtle()
    };
    let cells = [
        job_cell(marker, widths[0], theme::accent()),
        job_cell(included, widths[1], theme::subtle()),
        job_cell(&job.job_id, widths[2], theme::accent()),
        job_cell(&job.state, widths[3], job_state_style(&job.state)),
        job_cell(
            &crate::ui_view_models::campaign_job_attempt_cell(job),
            widths[4],
            theme::subtle(),
        ),
        job_cell(&job.priority.to_string(), widths[5], theme::subtle()),
        job_cell(&job_cost_label(job), widths[6], theme::primary()),
        job_cell(&job_findings_label(job), widths[7], findings_style),
        job_cell(&job_scope_label(job), widths[8], theme::muted()),
    ];
    cells
        .into_iter()
        .enumerate()
        .flat_map(|(index, cell)| {
            (index > 0)
                .then_some(Span::raw("  "))
                .into_iter()
                .chain([cell])
        })
        .collect()
}

fn job_cell(value: &str, width: usize, style: Style) -> Span<'static> {
    Span::styled(pad(&fit(value, width), width), style)
}

fn job_findings_label(job: &CampaignJobSnapshot) -> String {
    job.findings
        .map(|count| count.to_string())
        .unwrap_or_else(|| "—".to_string())
}

pub(super) fn job_cost_label(job: &CampaignJobSnapshot) -> String {
    crate::ui_view_models::campaign_job_cost_label(job)
}

pub(super) fn job_state_style(state: &str) -> Style {
    match state {
        "completed" => theme::success(),
        "running" => theme::accent(),
        "failed" => theme::danger(),
        // Parked means "gave up pending operator action" (budget, prepare
        // failure) — actionable but not a crash, so it reads as warning.
        "parked" | "retry-wait" => theme::warn(),
        _ => theme::muted(),
    }
}

fn append_deck_footer(
    lines: &mut Vec<Line<'static>>,
    deck: &CampaignRouteState,
    area: Rect,
    linked_study: bool,
) {
    if !deck.has_dispatcher_failure_notice() {
        append_campaign_notice(lines, deck, area);
    }
    lines.push(blank());
    let commands = deck_commands(deck)
        .iter()
        .copied()
        .filter(|command| show_deck_command(command, linked_study))
        .collect::<Vec<_>>();
    lines.extend(command_list_lines(&commands, area.width as usize));
}

fn show_deck_command(command: &str, linked_study: bool) -> bool {
    !linked_study || !matches!(command, "q list" | "q jobs")
}

fn append_campaign_notice(lines: &mut Vec<Line<'static>>, deck: &CampaignRouteState, area: Rect) {
    if let Some(notice) = &deck.notice {
        lines.extend(
            wrap_text(notice, area.width.saturating_sub(2) as usize)
                .into_iter()
                .map(|line| Line::styled(format!("  {line}"), theme::warn())),
        );
        lines.push(blank());
    }
}

pub(super) fn deck_commands(deck: &CampaignRouteState) -> &'static [&'static str] {
    if deck.job_detail {
        return inspected_job_commands(deck);
    }
    if deck.dispatcher_stop_requested {
        return &[
            "j/k",
            "Stop requested",
            "saving partial work",
            "r refresh",
            "q list",
        ];
    }
    let batch_detail = deck
        .selected_campaign()
        .is_some_and(crate::app::is_fixed_study_snapshot);
    let completed_context = deck.selected_campaign().is_some_and(|campaign| {
        campaign.kind.as_deref() == Some("context-study")
            && campaign.jobs.iter().all(|job| job.state == "completed")
    });
    if deck.detail && completed_context {
        completed_generation_commands(deck)
    } else if deck.detail && batch_detail {
        fixed_work_commands(deck)
    } else if deck.detail {
        &[
            "j/k",
            "x include/exclude",
            "w workers",
            "L launch",
            "K stop",
            "e prompt",
            "r refresh",
            "q list",
        ]
    } else {
        &["j/k", "Enter jobs", "r refresh", "campaign <id>", "back"]
    }
}

fn inspected_job_commands(deck: &CampaignRouteState) -> &'static [&'static str] {
    if deck.dispatcher_stop_requested {
        return &[
            "Stop requested",
            "saving partial work",
            "q jobs",
            "r refresh",
        ];
    }
    if deck.dispatcher_pid.is_some() {
        return &[
            "↑↓ jobs",
            "K stop",
            "q jobs",
            "a plan/allowance",
            "PgUp/Dn read",
            "r refresh",
        ];
    }
    &[
        "↑↓ jobs",
        "q jobs",
        "a plan/allowance",
        "PgUp/Dn read",
        "r refresh",
    ]
}

const PAUSED_FIXED_WORK_COMMANDS: &[&str] = &[
    "j/k",
    "Enter inspect",
    "a plan/allowance",
    "work paused",
    "review plan before resuming",
    "R report",
    "r refresh",
    "q list",
];

fn fixed_work_commands(deck: &CampaignRouteState) -> &'static [&'static str] {
    let unfinished = deck.selected_campaign().is_some_and(|campaign| {
        campaign
            .jobs
            .iter()
            .any(|job| matches!(job.state.as_str(), "planned" | "running"))
    });
    if unfinished {
        &[
            "j/k",
            "Enter inspect",
            "a plan/allowance",
            "jobs frozen",
            "workers frozen",
            "L launch",
            "K stop",
            "r refresh",
            "q list",
        ]
    } else {
        settled_fixed_work_commands(deck)
    }
}

fn settled_fixed_work_commands(deck: &CampaignRouteState) -> &'static [&'static str] {
    if deck
        .selected_campaign()
        .is_some_and(|campaign| campaign.jobs.iter().any(|job| job.state == "parked"))
    {
        return PAUSED_FIXED_WORK_COMMANDS;
    }
    if deck
        .selected_campaign()
        .is_some_and(|campaign| campaign.jobs.iter().all(|job| job.state == "completed"))
    {
        &[
            "j/k",
            "Enter inspect",
            "a plan/allowance",
            "work finished",
            "R report",
            "r refresh",
            "q list",
        ]
    } else {
        &[
            "j/k",
            "Enter inspect",
            "a plan/allowance",
            "work ended",
            "new work needs a new plan",
            "R report",
            "r refresh",
            "q list",
        ]
    }
}

fn completed_generation_commands(deck: &CampaignRouteState) -> &'static [&'static str] {
    let scopes = deck.selected_campaign().is_some_and(|campaign| {
        campaign
            .jobs
            .iter()
            .any(|job| job.tool.as_deref() == Some("pack:suggest-scopes"))
    });
    if scopes {
        &["j/k", "a scope result", "r refresh", "q list"]
    } else {
        &["j/k", "a context result", "r refresh", "q list"]
    }
}

fn append_empty_deck(lines: &mut Vec<Line<'static>>) {
    lines.extend(empty_state_panel(
        "no campaigns planned",
        &["campaign plans live under .kuzushi/v3/campaigns/<id>/plan.json."],
        &[
            (
                "run campaign:plan {\"campaignId\": \"…\"}",
                "cross threats × shards into a ranked job matrix",
            ),
            ("campaign <id>", "open a campaign's job matrix directly"),
        ],
    ));
}

#[cfg(test)]
mod tests {
    use super::super::summary::campaign_spend_label;
    use super::*;
    use kuzushi_core::capabilities::campaign::{
        BatchGateStatus, BatchOperationalStatus, BatchSecurityGateStatus, ScanBatchGateOutcome,
        ScanBatchGatePolicy,
    };
    use kuzushi_core::findings::{BatchOccurrenceReport, BatchOccurrenceRow, IdentityFoldPolicy};
    use kuzushi_core::V2Config;

    fn line_width(line: &Line<'_>) -> usize {
        line.spans
            .iter()
            .map(|span| display_width(span.content.as_ref()))
            .sum()
    }

    #[test]
    fn campaign_tables_fit_narrow_area_budgets() {
        let deck = CampaignRouteState::default();
        let job = sample_job("job-日本語-long", "retry-wait");
        let campaign = CampaignSnapshot {
            campaign_id: "campaign-日本語-long".to_string(),
            kind: Some(kuzushi_core::capabilities::campaign::SCAN_BATCH_KIND.to_string()),
            requested_workers: Some(4),
            effective_workers: Some(1),
            parallel_safety_reason: Some("workspace exclusive".to_string()),
            tool: Some("sast:scan".to_string()),
            created_at_ms: None,
            paused_until_ms: None,
            budget_usd: None,
            job_budget_usd: None,
            fill_gaps: false,
            skipped_covered_cells: None,
            total_cost_usd: 0.0,
            provider_spend_unresolved: false,
            jobs: vec![job.clone()],
        };
        for width in [40, 60, 80] {
            let area = Rect::new(0, 0, width, 20);
            let list_widths = campaign_list_widths(area);
            let job_widths = job_list_widths(area);
            let campaign_line = campaign_row_line(&campaign, true, &list_widths);
            let compact = compact_job_table(&deck, &job_widths);
            let job_line = job_row_line(&deck, &job, true, &job_widths, compact);

            assert_eq!(table_width(&list_widths), width as usize);
            assert_eq!(table_width(&job_widths), width as usize);
            assert!(line_width(&campaign_line) <= width as usize);
            assert!(line_width(&job_line) <= width as usize);
        }
    }

    #[test]
    fn empty_deck_renders_plan_guidance() {
        let app = ShellApp::new(V2Config::default(), None);
        let text = rendered_text(&app);
        assert!(text.contains("no campaigns planned"), "{text}");
        assert!(text.contains("campaign:plan"), "{text}");
    }

    #[test]
    fn job_scope_label_prefers_threat_title() {
        let job = sample_job("j1", "planned");
        assert_eq!(job_scope_label(&job), "src/auth / Token forgery");
    }

    #[test]
    fn accepted_scope_identity_precedes_the_legacy_shard_label() {
        let mut job = sample_job("j1", "planned");
        job.input["scanScopeRef"] = serde_json::json!({"scopeId": "accepted-files"});
        assert_eq!(job_scope_label(&job), "accepted-files / Token forgery");
    }

    #[test]
    fn compact_rows_preserve_excluded_job_disposition() {
        let mut deck = CampaignRouteState::default();
        deck.excluded.insert("j1".into());
        let widths = job_list_widths(Rect::new(0, 0, 40, 12));
        let compact = compact_job_table(&deck, &widths);
        let line = job_row_line(&deck, &sample_job("j1", "planned"), true, &widths, compact);
        assert!(line.to_string().contains("▸ × j1"));
    }

    #[test]
    fn excluded_job_renders_dash_marker() {
        let mut deck = CampaignRouteState::default();
        deck.excluded.insert("j1".to_string());
        let widths = job_list_widths(Rect::new(0, 0, 120, 30));
        let compact = compact_job_table(&deck, &widths);
        let line = job_row_line(&deck, &sample_job("j1", "planned"), true, &widths, compact);
        let text = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(text.contains('—'), "{text}");
    }

    #[test]
    fn batch_config_withholds_cost_until_a_named_prior_exists() {
        let target = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router.campaign_mut().batch_scan_config =
            Some(crate::app::BatchScanConfig::load(target.path(), None));
        app.set_shell_view(crate::app::ShellView::Campaign);

        let text = rendered_text(&app);

        assert!(text.contains("PLAN A STUDY"), "{text}");
        assert!(text.contains("Provider requests: not estimated"), "{text}");
        assert!(text.contains("Dollar estimate: unavailable"), "{text}");
        assert!(text.contains("Requested 1 workers; 1 permitted"), "{text}");
    }

    #[test]
    fn batch_detail_renders_badge_occurrence_and_runs() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let deck = app.router.campaign_mut();
        deck.campaigns = vec![sample_campaign()];
        deck.detail = true;
        deck.active_batch_id = Some("batch-1".to_string());
        deck.active_batch_report = Some(sample_batch_report());

        let text = rendered_text(&app);

        assert!(text.contains("BATCH batch-1"), "{text}");
        assert!(text.contains("BATCH OCCURRENCE"), "{text}");
        assert!(text.contains("seen 2 / completed 3"), "{text}");
        assert!(text.contains("runs run-1, run-2"), "{text}");
        assert!(
            text.contains("Severity cutoff high: reached · 1 qualifying finding"),
            "{text}"
        );
        assert!(text.contains("work finished"), "{text}");
        assert!(
            !text.contains("L launch") && !text.contains("K stop"),
            "{text}"
        );
        assert!(!text.contains("x include/exclude"), "{text}");
    }

    #[test]
    fn context_study_names_every_tool_and_keeps_selected_attempt_details() {
        let mut campaign = sample_campaign();
        campaign.kind = Some("context-study".into());
        campaign.jobs = [
            "context:build",
            "entry-points:extract",
            "threat-model:build",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, tool)| {
            let mut job = sample_job(&format!("job-{index}"), "planned");
            job.tool = Some(tool.into());
            job
        })
        .collect();
        let mut deck = CampaignRouteState::default();
        deck.selected_job = 2;
        for width in [40, 60, 80, 96, 120, 160] {
            let mut lines = Vec::new();
            append_campaign_jobs(&mut lines, &deck, &campaign, Rect::new(0, 0, width, 12));
            let text = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            for tool in [
                "context:build",
                "entry-points:extract",
                "threat-model:build",
            ] {
                assert!(text.contains(tool), "{text}");
            }
            assert!(
                text.contains("job-2") && text.contains("0 total attempts"),
                "{text}"
            );
            assert!(lines.len() <= 6, "{text}");
        }
    }

    fn sample_job(job_id: &str, state: &str) -> CampaignJobSnapshot {
        CampaignJobSnapshot {
            job_id: job_id.to_string(),
            display_label: None,
            tool: Some("sast:scan".to_string()),
            shard: Some("src/auth".to_string()),
            threat_id: Some("T1".to_string()),
            threat_title: Some("Token forgery".to_string()),
            threat_source: None,
            priority: 40,
            prompt_path: None,
            input: serde_json::Value::Null,
            state: state.to_string(),
            attempts: 0,
            dispatches: Some(0),
            exit_code: None,
            cost_usd: None,
            provider_spend_unresolved: false,
            run_id: None,
            reason: None,
            findings: None,
        }
    }

    #[test]
    fn unknown_campaign_cost_never_looks_like_a_zero_charge() {
        let mut campaign = sample_campaign();
        assert_eq!(campaign_spend_label(&campaign), "cost unavailable");
        assert_eq!(job_cost_label(&campaign.jobs[0]), "unknown");
        campaign.jobs.push(sample_job("second", "running"));
        campaign.jobs[0].cost_usd = Some(1.25);
        campaign.total_cost_usd = 1.25;
        assert_eq!(
            campaign_spend_label(&campaign),
            "≥$1.25 reported · total unknown"
        );
        campaign.jobs[1].cost_usd = Some(0.0);
        assert_eq!(campaign_spend_label(&campaign), "$1.25 spent");
        campaign.provider_spend_unresolved = true;
        assert_eq!(
            campaign_spend_label(&campaign),
            "≥$1.25 reported · total unknown"
        );
    }

    #[test]
    fn an_unpriced_call_with_zero_observed_cost_stays_unknown() {
        let mut campaign = sample_campaign();
        campaign.jobs[0].cost_usd = Some(0.0);
        campaign.jobs[0].provider_spend_unresolved = true;
        campaign.provider_spend_unresolved = true;
        assert_eq!(job_cost_label(&campaign.jobs[0]), "unknown");
        assert_eq!(campaign_spend_label(&campaign), "cost unavailable");
    }

    #[test]
    fn finished_fixed_work_keeps_review_available_without_launch_or_kill_controls() {
        let mut campaign = sample_campaign();
        campaign.jobs.push(sample_job("failed", "failed"));
        let mut deck = CampaignRouteState::default();
        deck.detail = true;
        deck.campaigns = vec![campaign];
        assert!(deck_commands(&deck).contains(&"a plan/allowance"));
        assert!(!deck_commands(&deck).contains(&"L launch"));
        assert!(!deck_commands(&deck).contains(&"K stop"));
        assert!(deck_commands(&deck).contains(&"work ended"));
        assert!(!deck_commands(&deck).contains(&"L resume after review"));
        assert!(deck_commands(&deck).contains(&"new work needs a new plan"));
        assert!(!deck_commands(&deck).contains(&"work finished"));
        for state in ["planned", "running"] {
            deck.campaigns[0].jobs[0].state = state.into();
            assert!(deck_commands(&deck).contains(&"L launch"));
        }
    }

    #[test]
    fn parked_fixed_work_keeps_partial_report_and_review_visible() {
        let mut campaign = sample_campaign();
        let mut parked = sample_job("waiting", "parked");
        parked.reason = Some("allowance-exhausted".into());
        campaign.jobs.push(parked);
        let mut deck = CampaignRouteState::default();
        deck.detail = true;
        deck.campaigns = vec![campaign];
        let commands = deck_commands(&deck);
        assert!(commands.contains(&"work paused"));
        assert!(commands.contains(&"a plan/allowance"));
        assert!(commands.contains(&"R report"));
        assert!(!commands.contains(&"work finished"));
    }

    #[test]
    fn completed_scope_job_names_the_scope_result_and_keeps_launch_unavailable() {
        let mut campaign = sample_campaign();
        campaign.kind = Some("context-study".into());
        campaign.tool = Some("pack:suggest-scopes".into());
        campaign.jobs[0].tool = Some("pack:suggest-scopes".into());
        let mut deck = CampaignRouteState::default();
        deck.detail = true;
        deck.campaigns = vec![campaign];
        assert!(deck_commands(&deck).contains(&"a scope result"));
        assert!(!deck_commands(&deck).contains(&"a context result"));
        assert!(!deck_commands(&deck).contains(&"L launch"));
    }

    #[test]
    fn completed_context_jobs_show_full_recovery_notice_and_review_controls() {
        let mut campaign = sample_campaign();
        campaign.kind = Some("context-study".into());
        let mut deck = CampaignRouteState::default();
        deck.detail = true;
        deck.campaigns = vec![campaign];
        deck.notice = Some("Context result unavailable. Inspect the completed attempt; a replacement draft requires separate approval.".into());
        for width in [40, 60, 80, 96, 120, 160] {
            let mut lines = Vec::new();
            append_deck_footer(&mut lines, &deck, Rect::new(0, 0, width, 48), false);
            let text = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            assert!(text.contains("separate approval."), "{text}");
            assert!(
                !text.contains("L launch") && !text.contains("K stop"),
                "{text}"
            );
            assert!(lines.iter().all(|line| line_width(line) <= width as usize));
        }
        assert!(deck_commands(&deck).contains(&"a context result"));
        deck.campaigns[0].jobs[0].state = "planned".into();
        assert!(deck_commands(&deck).contains(&"L launch"));
    }

    pub(super) fn sample_campaign() -> CampaignSnapshot {
        CampaignSnapshot {
            campaign_id: "batch-1".to_string(),
            kind: Some(kuzushi_core::capabilities::campaign::SCAN_BATCH_KIND.to_string()),
            requested_workers: Some(4),
            effective_workers: Some(2),
            parallel_safety_reason: Some("shared read".to_string()),
            tool: Some("sast:scan".to_string()),
            created_at_ms: None,
            paused_until_ms: None,
            budget_usd: None,
            job_budget_usd: None,
            fill_gaps: false,
            skipped_covered_cells: None,
            total_cost_usd: 0.0,
            provider_spend_unresolved: false,
            jobs: vec![sample_job("trial-1", "completed")],
        }
    }

    fn sample_batch_report() -> BatchOccurrenceReport {
        BatchOccurrenceReport {
            schema_version: 1,
            batch_id: "batch-1".to_string(),
            equivalence_key: "eq-1".to_string(),
            identity_fold: IdentityFoldPolicy::Safe,
            planned: 4,
            completed: 3,
            failed: 1,
            pending: 0,
            gate: Some(sample_batch_gate()),
            trials: Vec::new(),
            rows: vec![BatchOccurrenceRow {
                fold_key: "finding-1".to_string(),
                identity_id: None,
                identity_basis: None,
                seen: 2,
                completed: 3,
                planned: 4,
                failed: 1,
                severities: vec!["high".to_string()],
                locations: vec!["src/auth.rs:12".to_string()],
                titles: vec!["unsafe auth flow".to_string()],
                fingerprints: vec!["finding-1".to_string()],
                run_ids: vec!["run-1".to_string(), "run-2".to_string()],
                representative_fingerprint: "finding-1".to_string(),
                representative_title: "unsafe auth flow".to_string(),
                representative_severity: "high".to_string(),
                representative_location: "src/auth.rs:12".to_string(),
            }],
        }
    }

    fn sample_batch_gate() -> ScanBatchGateOutcome {
        ScanBatchGateOutcome {
            schema_version: 1,
            batch_id: "batch-1".to_string(),
            equivalence_key: "eq-1".to_string(),
            policy: ScanBatchGatePolicy {
                fail_on: Some(kuzushi_core::findings::Severity::High),
                sarif: None,
            },
            status: BatchGateStatus::Failed,
            operational_status: BatchOperationalStatus::Complete,
            security_status: BatchSecurityGateStatus::Failed,
            threshold: Some(kuzushi_core::findings::Severity::High),
            planned_trials: 4,
            completed_trials: 4,
            failed_trials: 0,
            pending_trials: 0,
            completed_run_ids: vec!["run-1".to_string(), "run-2".to_string()],
            blocking_safe_fold_count: 1,
            sarif_written: false,
            binding: kuzushi_core::capabilities::campaign::ScanBatchGateBinding {
                logical_terminal_state_sha256: "terminal-sha".to_string(),
                blocking_findings_sha256: "findings-sha".to_string(),
                sarif_path: None,
                sarif_sha256: None,
            },
            recorded_at_ms: 1,
        }
    }

    #[test]
    fn deck_list_renders_the_workspace_trend_strip_when_folded() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router.campaign_mut().trend = Some(
            kuzushi_core::capabilities::campaign::trend::trend_metrics(&[], 12.5),
        );
        let text = rendered_text(&app);
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(text.contains("TREND FP rate"), "{text}");
        assert!(
            text.contains("(no decisions) · 0 confirmed · $12.50 spent"),
            "{text}"
        );
    }

    #[test]
    fn findings_column_renders_count_or_dash() {
        let mut job = sample_job("j1", "completed");
        assert_eq!(job_findings_label(&job), "—");
        job.findings = Some(12);
        assert_eq!(job_findings_label(&job), "12");
    }

    fn rendered_text(app: &ShellApp) -> String {
        campaign_lines(app, Rect::new(0, 0, 120, 30))
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod attempt_display_tests {
    use super::*;
    use crate::app::CampaignRouteState;

    #[test]
    fn resumed_jobs_keep_total_and_pass_identity_at_every_width() {
        let mut campaign = super::tests::sample_campaign();
        campaign.kind = Some("scan-batch".into());
        let job = campaign.jobs.first_mut().unwrap();
        job.display_label = Some("Discovery · pass 1/3".into());
        job.attempts = 1;
        job.dispatches = Some(2);
        for width in [40, 60, 80, 96, 120, 160] {
            let mut lines = Vec::new();
            super::super::fixed_jobs::append_fixed_jobs(
                &mut lines,
                &CampaignRouteState::default(),
                &campaign,
                width,
            );
            let text = lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(lines.iter().all(|line| line.width() <= width), "{text}");
            assert!(
                text.contains("pass 1/3") && text.contains("2 total attempts"),
                "{text}"
            );
        }
    }
}

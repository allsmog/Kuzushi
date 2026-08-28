use super::batch_occurrence_lines::append_batch_occurrence;
use super::batch_scan_config_lines::append_batch_scan_config;
use super::*;
use crate::app::CampaignRouteState;
use kuzushi_core::capabilities::campaign::snapshot::{CampaignJobSnapshot, CampaignSnapshot};

const CAMPAIGN_LIST_WIDTHS: [usize; 4] = [18, 14, 6, 30];
const JOB_LIST_WIDTHS: [usize; 7] = [4, 22, 10, 4, 5, 12, 5];
const BURN_BAR_CELLS: usize = 10;

/// The Campaign deck: list mode is one row per planned campaign; detail mode
/// is the selected campaign's ranked job matrix with include/exclude marks.
/// All lifecycle truth comes from the snapshot fold (plan + dispatcher queue).
pub(crate) fn campaign_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let deck = app.router.campaign();
    let mut lines = context_strip(app, area);
    lines.push(blank());
    if let Some(config) = deck.batch_scan_config.as_ref() {
        append_batch_scan_config(&mut lines, config, area);
        return lines;
    }
    match deck.selected_campaign().filter(|_| deck.detail) {
        Some(campaign) => append_campaign_detail(&mut lines, deck, campaign, area),
        None => append_campaign_list(&mut lines, deck, area),
    }
    append_deck_footer(&mut lines, deck, area);
    lines
}

fn append_campaign_list(lines: &mut Vec<Line<'static>>, deck: &CampaignRouteState, area: Rect) {
    lines.push(divider("CAMPAIGNS", area.width));
    if let Some(trend) = &deck.trend {
        lines.push(Line::styled(
            format!("  {}", trend.strip_label()),
            theme::subtle(),
        ));
        if let Some(history) =
            kuzushi_core::capabilities::campaign::trend_history::history_strip_label(
                &deck.trend_history,
            )
        {
            lines.push(Line::styled(format!("  {history}"), theme::subtle()));
        }
        lines.push(blank());
    }
    if deck.campaigns.is_empty() {
        append_empty_deck(lines);
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

fn states_label(campaign: &CampaignSnapshot) -> String {
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
    lines.push(divider(&campaign_detail_title(campaign), area.width));
    lines.push(detail_summary_line(deck, campaign));
    append_campaign_operational_detail(lines, campaign);
    lines.push(blank());
    let widths = job_list_widths(area);
    lines.push(aligned_header(
        &[
            "  ",
            "in",
            "job",
            "state",
            "att",
            "prio",
            "cost",
            "find",
            "shard / threat",
        ],
        &widths,
    ));
    for (index, job) in campaign.jobs.iter().enumerate() {
        lines.push(job_row_line(deck, job, index == deck.selected_job, &widths));
    }
    if let Some(report) = deck
        .active_batch_report()
        .filter(|report| report.batch_id == campaign.campaign_id)
    {
        append_batch_occurrence(lines, report, area);
    }
}

fn campaign_detail_title(campaign: &CampaignSnapshot) -> String {
    let kind = if crate::app::is_scan_batch_snapshot(campaign) {
        "BATCH"
    } else {
        "CAMPAIGN"
    };
    format!("{kind} {}", campaign.campaign_id)
}

fn append_campaign_operational_detail(lines: &mut Vec<Line<'static>>, campaign: &CampaignSnapshot) {
    append_optional_campaign_detail(lines, batch_worker_policy_label(campaign), theme::subtle());
    append_optional_campaign_detail(
        lines,
        burn_bar_label(campaign.total_cost_usd, campaign.budget_usd),
        burn_bar_style(campaign.total_cost_usd, campaign.budget_usd),
    );
    append_optional_campaign_detail(
        lines,
        job_budget_label(campaign.job_budget_usd),
        theme::subtle(),
    );
    append_optional_campaign_detail(
        lines,
        gap_fill_label(campaign.fill_gaps, campaign.skipped_covered_cells),
        theme::subtle(),
    );
    append_optional_campaign_detail(
        lines,
        pause_countdown_label(campaign.paused_until_ms, unix_now_ms()),
        theme::warn(),
    );
    append_optional_campaign_detail(
        lines,
        campaign.provider_spend_unresolved.then(|| {
            "provider spend is incomplete; shown cost is a lower bound and dispatch is halted"
                .to_string()
        }),
        theme::warn(),
    );
}

fn append_optional_campaign_detail(
    lines: &mut Vec<Line<'static>>,
    label: Option<String>,
    style: Style,
) {
    if let Some(label) = label {
        lines.push(Line::styled(format!("  {label}"), style));
    }
}

fn detail_summary_line(deck: &CampaignRouteState, campaign: &CampaignSnapshot) -> Line<'static> {
    let dispatcher = deck
        .dispatcher_pid
        .map(|pid| format!("dispatcher pid {pid}"))
        .unwrap_or_else(|| "no deck-launched dispatcher".to_string());
    Line::styled(
        format!(
            "  {} job(s) · {} · {} · {} · {}",
            campaign.jobs.len(),
            states_label(campaign),
            campaign_worker_label(deck, campaign),
            campaign_spend_label(campaign),
            dispatcher,
        ),
        theme::subtle(),
    )
}

fn campaign_worker_label(deck: &CampaignRouteState, campaign: &CampaignSnapshot) -> String {
    match (campaign.requested_workers, campaign.effective_workers) {
        (Some(requested), Some(effective)) => {
            format!("workers {effective} frozen (requested {requested})")
        }
        _ => format!("workers {}", deck.workers),
    }
}

fn batch_worker_policy_label(campaign: &CampaignSnapshot) -> Option<String> {
    if !crate::app::is_scan_batch_snapshot(campaign) {
        return None;
    }
    Some(match campaign.parallel_safety_reason.as_deref() {
        Some(reason) => format!("parallel safety — {reason}"),
        None => "parallel safety — frozen by the immutable batch plan".to_string(),
    })
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
) -> Line<'static> {
    let marker = if selected { "▸" } else { " " };
    let included = if deck.excluded.contains(&job.job_id) {
        "—"
    } else {
        "✓"
    };
    Line::from(job_row_spans(job, marker, included, widths))
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
        job_cell(&job.attempts.to_string(), widths[4], theme::subtle()),
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

fn job_cost_label(job: &CampaignJobSnapshot) -> String {
    job.cost_usd
        .map(|cost| {
            if job.provider_spend_unresolved {
                format!("≥${cost:.2}")
            } else {
                format!("${cost:.2}")
            }
        })
        .unwrap_or_else(|| "—".to_string())
}

fn campaign_spend_label(campaign: &CampaignSnapshot) -> String {
    if campaign.provider_spend_unresolved {
        format!("≥${:.2} spent", campaign.total_cost_usd)
    } else {
        format!("${:.2} spent", campaign.total_cost_usd)
    }
}

fn job_scope_label(job: &CampaignJobSnapshot) -> String {
    let shard = job.shard.as_deref().unwrap_or("workspace");
    match job.threat_title.as_deref().or(job.threat_id.as_deref()) {
        Some(threat) => format!("{shard} / {threat}"),
        None => shard.to_string(),
    }
}

fn job_state_style(state: &str) -> Style {
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

/// `▮▮▮▯▯▯▯▯▯▯ $3.20/$15.00 (21%)` — only when the last dispatcher declared
/// Gap-fill provenance — this plan deliberately skipped already-covered
/// shard × source cells, so a short job list is convergence, not a bug.
fn gap_fill_label(fill_gaps: bool, skipped_covered_cells: Option<u64>) -> Option<String> {
    fill_gaps.then(|| {
        format!(
            "gap-fill plan — {} already-covered cell(s) skipped at planning",
            skipped_covered_cells.unwrap_or(0)
        )
    })
}

/// Per-job cap disclosure — running jobs are killed and parked
/// `over-budget` when their live spend crosses this ceiling.
fn job_budget_label(job_budget_usd: Option<f64>) -> Option<String> {
    let cap = job_budget_usd.filter(|cap| *cap > 0.0)?;
    Some(format!(
        "job cap ${cap:.2} — a running job crossing it is stopped and parked over-budget"
    ))
}

/// a budget; an unlimited campaign shows plain spend in the summary line.
fn burn_bar_label(spent_usd: f64, budget_usd: Option<f64>) -> Option<String> {
    let budget = budget_usd.filter(|budget| *budget > 0.0)?;
    let ratio = (spent_usd / budget).clamp(0.0, 1.0);
    let filled = (ratio * BURN_BAR_CELLS as f64).round() as usize;
    let bar: String = "▮".repeat(filled) + &"▯".repeat(BURN_BAR_CELLS - filled);
    Some(format!(
        "{bar} ${spent_usd:.2}/${budget:.2} ({:.0}%)",
        ratio * 100.0
    ))
}

fn burn_bar_style(spent_usd: f64, budget_usd: Option<f64>) -> Style {
    match budget_usd {
        Some(budget) if budget > 0.0 && spent_usd / budget >= 0.8 => theme::danger(),
        Some(budget) if budget > 0.0 && spent_usd / budget >= 0.5 => theme::warn(),
        _ => theme::success(),
    }
}

/// Countdown to the end of a dispatcher quota-wall pause; `None` once the
/// pause expired (the queue keeps the stale timestamp until the next event).
fn pause_countdown_label(paused_until_ms: Option<u64>, now_ms: u64) -> Option<String> {
    let remaining_ms = paused_until_ms?.checked_sub(now_ms).filter(|ms| *ms > 0)?;
    let seconds = remaining_ms.div_ceil(1000);
    let clock = if seconds >= 60 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    };
    Some(format!("⏸ quota-wall pause — dispatch resumes in {clock}"))
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn append_deck_footer(lines: &mut Vec<Line<'static>>, deck: &CampaignRouteState, area: Rect) {
    if let Some(notice) = &deck.notice {
        lines.push(blank());
        lines.push(Line::styled(format!("  {notice}"), theme::warn()));
    }
    lines.push(blank());
    let batch_detail = deck
        .selected_campaign()
        .is_some_and(crate::app::is_scan_batch_snapshot);
    let commands: &[&str] = if deck.detail && batch_detail {
        &[
            "j/k",
            "trials frozen",
            "workers frozen",
            "L launch",
            "K kill",
            "r refresh",
            "q list",
        ]
    } else if deck.detail {
        &[
            "j/k",
            "x include/exclude",
            "w workers",
            "L launch",
            "K kill",
            "e prompt",
            "r refresh",
            "q list",
        ]
    } else {
        &["j/k", "Enter jobs", "r refresh", "campaign <id>", "back"]
    };
    lines.push(command_list_line(commands, area.width as usize));
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
            let job_line = job_row_line(&deck, &job, true, &job_widths);

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
    fn excluded_job_renders_dash_marker() {
        let mut deck = CampaignRouteState::default();
        deck.excluded.insert("j1".to_string());
        let widths = job_list_widths(Rect::new(0, 0, 120, 30));
        let line = job_row_line(&deck, &sample_job("j1", "planned"), true, &widths);
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

        let text = rendered_text(&app);

        assert!(text.contains("SCAN BATCH"), "{text}");
        assert!(text.contains("cost not estimated"), "{text}");
        assert!(text.contains("requested 1 → effective 1"), "{text}");
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
        assert!(text.contains("runs run-1,run-2"), "{text}");
        assert!(
            text.contains("gate failed · operational complete · security failed · blocking 1"),
            "{text}"
        );
        assert!(text.contains("trials frozen"), "{text}");
        assert!(!text.contains("x include/exclude"), "{text}");
    }

    fn sample_job(job_id: &str, state: &str) -> CampaignJobSnapshot {
        CampaignJobSnapshot {
            job_id: job_id.to_string(),
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
            exit_code: None,
            cost_usd: None,
            provider_spend_unresolved: false,
            run_id: None,
            reason: None,
            findings: None,
        }
    }

    fn sample_campaign() -> CampaignSnapshot {
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
    fn burn_bar_scales_and_hides_without_budget() {
        assert_eq!(
            burn_bar_label(3.0, Some(15.0)).unwrap(),
            "▮▮▯▯▯▯▯▯▯▯ $3.00/$15.00 (20%)"
        );
        assert_eq!(
            burn_bar_label(20.0, Some(15.0)).unwrap(),
            "▮▮▮▮▮▮▮▮▮▮ $20.00/$15.00 (100%)"
        );
        assert!(burn_bar_label(3.0, None).is_none());
        assert!(burn_bar_label(3.0, Some(0.0)).is_none());
    }

    #[test]
    fn job_cap_label_discloses_the_ceiling_and_hides_when_unset() {
        assert_eq!(
            job_budget_label(Some(5.0)).unwrap(),
            "job cap $5.00 — a running job crossing it is stopped and parked over-budget"
        );
        assert!(job_budget_label(None).is_none());
        assert!(job_budget_label(Some(0.0)).is_none());
    }

    #[test]
    fn gap_fill_label_discloses_skipped_cells_only_for_gap_fill_plans() {
        assert_eq!(
            gap_fill_label(true, Some(3)).unwrap(),
            "gap-fill plan — 3 already-covered cell(s) skipped at planning"
        );
        assert_eq!(
            gap_fill_label(true, None).unwrap(),
            "gap-fill plan — 0 already-covered cell(s) skipped at planning"
        );
        assert!(gap_fill_label(false, Some(3)).is_none());
    }

    #[test]
    fn pause_countdown_only_renders_future_pauses() {
        assert_eq!(
            pause_countdown_label(Some(100_000), 8_000).unwrap(),
            "⏸ quota-wall pause — dispatch resumes in 1m 32s"
        );
        assert_eq!(
            pause_countdown_label(Some(9_500), 8_000).unwrap(),
            "⏸ quota-wall pause — dispatch resumes in 2s"
        );
        assert!(pause_countdown_label(Some(8_000), 8_000).is_none());
        assert!(pause_countdown_label(Some(1_000), 8_000).is_none());
        assert!(pause_countdown_label(None, 8_000).is_none());
    }

    #[test]
    fn deck_list_renders_the_workspace_trend_strip_when_folded() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router.campaign_mut().trend = Some(
            kuzushi_core::capabilities::campaign::trend::trend_metrics(&[], 12.5),
        );
        let text = rendered_text(&app);
        assert!(
            text.contains("TREND  FP rate — (no decisions) · 0 confirmed · $12.50 spent"),
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

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
    let fixed_used = 2 + id + tool + jobs + states + 10;
    [2, id, tool, jobs, states.max(value_width(area, fixed_used))]
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
            format!("{}  ", pad(&fit(&campaign.campaign_id, widths[1]), widths[1])),
            theme::accent(),
        ),
        Span::styled(
            format!(
                "{}  ",
                pad(&fit(campaign.tool.as_deref().unwrap_or("—"), widths[2]), widths[2])
            ),
            theme::subtle(),
        ),
        Span::styled(
            format!("{}  ", pad(&campaign.jobs.len().to_string(), widths[3])),
            theme::primary(),
        ),
        Span::styled(
            format!("{}  ", pad(&fit(&states_label(campaign), widths[4]), widths[4])),
            theme::primary(),
        ),
    ])
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
    lines.push(divider(
        &format!("CAMPAIGN {}", campaign.campaign_id),
        area.width,
    ));
    lines.push(detail_summary_line(deck, campaign));
    if let Some(burn) = burn_bar_label(campaign.total_cost_usd, campaign.budget_usd) {
        lines.push(Line::styled(
            format!("  {burn}"),
            burn_bar_style(campaign.total_cost_usd, campaign.budget_usd),
        ));
    }
    if let Some(cap) = job_budget_label(campaign.job_budget_usd) {
        lines.push(Line::styled(format!("  {cap}"), theme::subtle()));
    }
    if let Some(gap) = gap_fill_label(campaign.fill_gaps, campaign.skipped_covered_cells) {
        lines.push(Line::styled(format!("  {gap}"), theme::subtle()));
    }
    if let Some(countdown) = pause_countdown_label(campaign.paused_until_ms, unix_now_ms()) {
        lines.push(Line::styled(format!("  {countdown}"), theme::warn()));
    }
    lines.push(blank());
    let widths = job_list_widths(area);
    lines.push(aligned_header(
        &["  ", "in", "job", "state", "att", "prio", "cost", "find", "shard / threat"],
        &widths,
    ));
    for (index, job) in campaign.jobs.iter().enumerate() {
        lines.push(job_row_line(deck, job, index == deck.selected_job, &widths));
    }
}

fn detail_summary_line(deck: &CampaignRouteState, campaign: &CampaignSnapshot) -> Line<'static> {
    let dispatcher = deck
        .dispatcher_pid
        .map(|pid| format!("dispatcher pid {pid}"))
        .unwrap_or_else(|| "no deck-launched dispatcher".to_string());
    Line::styled(
        format!(
            "  {} job(s) · {} · workers {} · ${:.2} spent · {}",
            campaign.jobs.len(),
            states_label(campaign),
            deck.workers,
            campaign.total_cost_usd,
            dispatcher,
        ),
        theme::subtle(),
    )
}

fn job_list_widths(area: Rect) -> [usize; 9] {
    let [marker, job, state, attempts, priority, cost, findings] = JOB_LIST_WIDTHS;
    let fixed_used = 2 + marker + job + state + attempts + priority + cost + findings + 18;
    [
        2,
        marker,
        job,
        state,
        attempts,
        priority,
        cost,
        findings,
        value_width(area, fixed_used),
    ]
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
    Line::from(vec![
        Span::styled(format!("{}  ", pad(marker, widths[0])), theme::accent()),
        Span::styled(format!("{}  ", pad(included, widths[1])), theme::subtle()),
        Span::styled(
            format!("{}  ", pad(&fit(&job.job_id, widths[2]), widths[2])),
            theme::accent(),
        ),
        Span::styled(
            format!("{}  ", pad(&job.state, widths[3])),
            job_state_style(&job.state),
        ),
        Span::styled(
            format!("{}  ", pad(&job.attempts.to_string(), widths[4])),
            theme::subtle(),
        ),
        Span::styled(
            format!("{}  ", pad(&job.priority.to_string(), widths[5])),
            theme::subtle(),
        ),
        Span::styled(
            format!("{}  ", pad(&job_cost_label(job), widths[6])),
            theme::primary(),
        ),
        Span::styled(
            format!("{}  ", pad(&job_findings_label(job), widths[7])),
            if job.findings.unwrap_or(0) > 0 {
                theme::warn()
            } else {
                theme::subtle()
            },
        ),
        Span::styled(
            format!("{}  ", pad(&fit(&job_scope_label(job), widths[8]), widths[8])),
            theme::muted(),
        ),
    ])
}

fn job_findings_label(job: &CampaignJobSnapshot) -> String {
    job.findings
        .map(|count| count.to_string())
        .unwrap_or_else(|| "—".to_string())
}

fn job_cost_label(job: &CampaignJobSnapshot) -> String {
    job.cost_usd
        .map(|cost| format!("${cost:.2}"))
        .unwrap_or_else(|| "—".to_string())
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
    let commands: &[&str] = if deck.detail {
        &["j/k", "x include/exclude", "w workers", "L launch", "K kill", "e prompt", "r refresh", "q list"]
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
    use kuzushi_core::V2Config;

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
            run_id: None,
            reason: None,
            findings: None,
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
        app.router.campaign_mut().trend =
            Some(kuzushi_core::capabilities::campaign::trend::trend_metrics(
                &[],
                12.5,
            ));
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

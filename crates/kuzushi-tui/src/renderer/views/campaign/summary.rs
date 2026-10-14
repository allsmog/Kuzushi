use super::campaign_lines::states_label;
use super::*;
use crate::app::CampaignRouteState;
use kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot;

const BURN_BAR_CELLS: usize = 10;

pub(super) fn append_campaign_summary(
    lines: &mut Vec<Line<'static>>,
    deck: &CampaignRouteState,
    campaign: &CampaignSnapshot,
    width: usize,
) {
    append_campaign_heading(lines, campaign, width);
    let fields = summary_fields(deck, campaign);
    let joined = fields.join(" · ");
    if display_width(&joined) <= width.saturating_sub(4) {
        push_deck_text(lines, &joined, width, theme::subtle());
    } else {
        for field in fields {
            push_deck_text(lines, &field, width, theme::subtle());
        }
    }
    append_operational_detail(lines, campaign, width);
}

fn append_campaign_heading(
    lines: &mut Vec<Line<'static>>,
    campaign: &CampaignSnapshot,
    width: usize,
) {
    let title = campaign_detail_title(campaign);
    if display_width(&title) + 6 <= width {
        lines.push(divider(&title, width as u16));
        return;
    }
    lines.push(divider(campaign_kind_label(campaign), width as u16));
    push_deck_text(lines, &campaign.campaign_id, width, theme::accent());
}

fn summary_fields(deck: &CampaignRouteState, campaign: &CampaignSnapshot) -> [String; 4] {
    let dispatcher = deck
        .dispatcher_pid
        .map(|pid| dispatcher_label(pid, deck.dispatcher_stop_requested))
        .unwrap_or_else(|| "no deck-launched dispatcher".into());
    [
        format!(
            "{} job(s) · {}",
            campaign.jobs.len(),
            states_label(campaign)
        ),
        campaign_worker_label(deck, campaign),
        campaign_spend_label(campaign),
        dispatcher,
    ]
}

fn append_operational_detail(
    lines: &mut Vec<Line<'static>>,
    campaign: &CampaignSnapshot,
    width: usize,
) {
    let fields = [
        (batch_worker_policy_label(campaign), theme::subtle()),
        (
            burn_bar_label(campaign.total_cost_usd, campaign.budget_usd),
            burn_bar_style(campaign.total_cost_usd, campaign.budget_usd),
        ),
        (job_budget_label(campaign.job_budget_usd), theme::subtle()),
        (
            gap_fill_label(campaign.fill_gaps, campaign.skipped_covered_cells),
            theme::subtle(),
        ),
        (
            pause_countdown_label(campaign.paused_until_ms, unix_now_ms()),
            theme::warn(),
        ),
        (
            campaign.provider_spend_unresolved.then(|| {
                "provider cost evidence is incomplete; dollar total is unknown".to_string()
            }),
            theme::warn(),
        ),
    ];
    for (label, style) in fields {
        if let Some(label) = label {
            push_deck_text(lines, &label, width, style);
        }
    }
}

fn campaign_detail_title(campaign: &CampaignSnapshot) -> String {
    format!("{} {}", campaign_kind_label(campaign), campaign.campaign_id)
}

fn campaign_kind_label(campaign: &CampaignSnapshot) -> &'static str {
    if crate::app::is_scan_batch_snapshot(campaign) {
        "BATCH"
    } else {
        "CAMPAIGN"
    }
}

fn dispatcher_label(pid: u32, stopping: bool) -> String {
    if stopping {
        format!("dispatcher {pid} stopping; saving partial work")
    } else {
        format!("dispatcher pid {pid}")
    }
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
        Some(reason) => format!("parallel safety · {reason}"),
        None => "parallel safety · frozen by the immutable batch plan".to_string(),
    })
}

pub(super) fn campaign_spend_label(campaign: &CampaignSnapshot) -> String {
    let missing_cost = campaign
        .jobs
        .iter()
        .any(|job| job.cost_usd.is_none() && job.state != "planned");
    if missing_cost || campaign.provider_spend_unresolved {
        return if campaign.total_cost_usd <= 0.0 {
            "cost unavailable".into()
        } else {
            format!("≥${:.2} reported · total unknown", campaign.total_cost_usd)
        };
    }
    format!("${:.2} spent", campaign.total_cost_usd)
}

/// Describes source/scope cells deliberately skipped by this plan.
fn gap_fill_label(fill_gaps: bool, skipped_covered_cells: Option<u64>) -> Option<String> {
    fill_gaps.then(|| {
        format!(
            "gap-fill plan · {} already-covered cell(s) skipped at planning",
            skipped_covered_cells.unwrap_or(0)
        )
    })
}

/// Per-job cap disclosure · running jobs are killed and parked
/// `over-budget` when their live spend crosses this ceiling.
fn job_budget_label(job_budget_usd: Option<f64>) -> Option<String> {
    let cap = job_budget_usd.filter(|cap| *cap > 0.0)?;
    Some(format!(
        "job cap ${cap:.2} · a running job crossing it is stopped and parked over-budget"
    ))
}

/// Shows the declared campaign budget alongside reported spend.
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
    Some(format!("⏸ quota-wall pause · dispatch resumes in {clock}"))
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
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
            "job cap $5.00 · a running job crossing it is stopped and parked over-budget"
        );
        assert!(job_budget_label(None).is_none());
        assert!(job_budget_label(Some(0.0)).is_none());
    }

    #[test]
    fn gap_fill_label_discloses_skipped_cells_only_for_gap_fill_plans() {
        assert_eq!(
            gap_fill_label(true, Some(3)).unwrap(),
            "gap-fill plan · 3 already-covered cell(s) skipped at planning"
        );
        assert_eq!(
            gap_fill_label(true, None).unwrap(),
            "gap-fill plan · 0 already-covered cell(s) skipped at planning"
        );
        assert!(gap_fill_label(false, Some(3)).is_none());
    }

    #[test]
    fn pause_countdown_only_renders_future_pauses() {
        assert_eq!(
            pause_countdown_label(Some(100_000), 8_000).unwrap(),
            "⏸ quota-wall pause · dispatch resumes in 1m 32s"
        );
        assert_eq!(
            pause_countdown_label(Some(9_500), 8_000).unwrap(),
            "⏸ quota-wall pause · dispatch resumes in 2s"
        );
        assert!(pause_countdown_label(Some(8_000), 8_000).is_none());
        assert!(pause_countdown_label(Some(1_000), 8_000).is_none());
        assert!(pause_countdown_label(None, 8_000).is_none());
    }
}

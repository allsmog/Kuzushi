//! Campaign deck behaviors: disk-snapshot refresh, cursor interaction, and
//! detached dispatcher launch/kill. The deck never executes jobs in-process —
//! Launch spawns `kuzushi campaign run` in its own process group, so closing
//! the shell never kills a campaign.

use super::state_transitions::{InputUpdate, ViewHotkeyAction};
use super::*;
use anyhow::Context;
use kuzushi_core::capabilities::campaign::campaign_dir;
use kuzushi_core::capabilities::campaign::snapshot::{
    campaign_ids, load_campaign_snapshot, CampaignSnapshot,
};
use std::path::Path;

impl ShellApp {
    pub(crate) fn open_campaign_view(&mut self, requested: Option<String>) {
        self.refresh_campaign_deck();
        if let Some(campaign_id) = requested {
            self.select_campaign(&campaign_id);
        }
        self.set_shell_view(ShellView::Campaign);
        self.log("campaign", "campaign deck");
    }

    fn select_campaign(&mut self, campaign_id: &str) {
        let deck = self.router.campaign_mut();
        let position = deck
            .campaigns
            .iter()
            .position(|campaign| campaign.campaign_id == campaign_id);
        match position {
            Some(index) => {
                deck.selected_campaign = index;
                deck.selected_job = 0;
                deck.excluded.clear();
                deck.detail = true;
            }
            None => deck.notice = Some(format!("campaign {campaign_id:?} not found")),
        }
    }

    pub(crate) fn refresh_campaign_deck(&mut self) {
        let Some(target) = self.target_path_buf().cloned() else {
            self.router.campaign_mut().notice =
                Some("select a target to load campaigns".to_string());
            return;
        };
        let (campaigns, unreadable) = load_campaign_snapshots(&target);
        let spend = campaigns
            .iter()
            .map(|campaign| campaign.total_cost_usd)
            .sum();
        let trend = kuzushi_core::capabilities::campaign::trend::trend_metrics(
            self.review_decisions(),
            spend,
        );
        let history = refresh_trend_history(&target, &trend);
        let deck = self.router.campaign_mut();
        deck.trend = Some(trend);
        deck.trend_history = history;
        deck.campaigns = campaigns;
        deck.selected_campaign = deck
            .selected_campaign
            .min(deck.campaigns.len().saturating_sub(1));
        deck.selected_job = deck.selected_job.min(deck.detail_job_ceiling());
        deck.notice = (unreadable > 0)
            .then(|| format!("{unreadable} campaign dir(s) had no readable plan"));
    }

    /// Recompute only the workspace trend (the Report route renders the same
    /// strip as the deck) without disturbing deck cursor or campaign state.
    pub(crate) fn refresh_workspace_trend(&mut self) {
        let Some(target) = self.target_path_buf().cloned() else {
            return;
        };
        let trend = kuzushi_core::capabilities::campaign::trend::trend_metrics(
            self.review_decisions(),
            kuzushi_core::capabilities::campaign::trend::workspace_campaign_spend(&target),
        );
        let history = refresh_trend_history(&target, &trend);
        let deck = self.router.campaign_mut();
        deck.trend = Some(trend);
        deck.trend_history = history;
    }

    pub(crate) fn apply_campaign_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        match action {
            ViewHotkeyAction::CampaignCursorPrevious => self.campaign_deck_edit(|deck| {
                deck.move_cursor(-1);
            }),
            ViewHotkeyAction::CampaignCursorNext => self.campaign_deck_edit(|deck| {
                deck.move_cursor(1);
            }),
            ViewHotkeyAction::CampaignOpenDetail => self.campaign_deck_edit(|deck| {
                deck.detail = deck.selected_campaign().is_some();
            }),
            ViewHotkeyAction::CampaignBackToList => self.campaign_deck_edit(|deck| {
                deck.detail = false;
            }),
            ViewHotkeyAction::CampaignToggleExclude => self.campaign_deck_edit(|deck| {
                deck.toggle_selected_exclusion();
            }),
            ViewHotkeyAction::CampaignCycleWorkers => self.campaign_deck_edit(|deck| {
                deck.cycle_workers();
            }),
            ViewHotkeyAction::CampaignLaunch => {
                self.campaign_launch();
                InputUpdate::handled()
            }
            ViewHotkeyAction::CampaignKill => {
                self.campaign_kill();
                InputUpdate::handled()
            }
            ViewHotkeyAction::CampaignShowPrompt => {
                self.campaign_show_prompt();
                InputUpdate::handled()
            }
            ViewHotkeyAction::CampaignRefresh => {
                self.refresh_campaign_deck();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
        }
    }

    fn campaign_deck_edit(
        &mut self,
        edit: impl FnOnce(&mut CampaignRouteState),
    ) -> InputUpdate {
        edit(self.router.campaign_mut());
        InputUpdate::handled()
    }

    /// Launch = spawn a detached dispatcher over the included job set. The
    /// deck records only the pid it spawned; dispatchers started elsewhere
    /// stay visible through queue state alone.
    fn campaign_launch(&mut self) {
        let Some((target, campaign_id, args)) = self.campaign_launch_spec() else {
            return;
        };
        let spawned = spawn_detached_dispatcher(&target, &campaign_id, &args);
        let deck = self.router.campaign_mut();
        match spawned {
            Ok(pid) => {
                deck.dispatcher_pid = Some(pid);
                deck.notice = Some(format!(
                    "dispatcher pid {pid} — logs: campaigns/{campaign_id}/logs/dispatcher.log"
                ));
            }
            Err(error) => deck.notice = Some(format!("launch failed: {error:#}")),
        }
    }

    fn campaign_launch_spec(&mut self) -> Option<(std::path::PathBuf, String, Vec<String>)> {
        let Some(target) = self.target_path_buf().cloned() else {
            self.router.campaign_mut().notice = Some("launch requires a target".to_string());
            return None;
        };
        let deck = self.router.campaign();
        let Some(campaign) = deck.selected_campaign() else {
            self.router.campaign_mut().notice = Some("no campaign selected".to_string());
            return None;
        };
        let campaign_id = campaign.campaign_id.clone();
        let total_jobs = campaign.jobs.len();
        let included = deck.included_job_ids();
        if included.is_empty() {
            self.router.campaign_mut().notice =
                Some("every job is excluded — nothing to launch".to_string());
            return None;
        }
        let args = dispatcher_args(&campaign_id, &target, deck.workers, &included, total_jobs);
        Some((target, campaign_id, args))
    }

    /// Kill only the dispatcher THIS deck launched (whole process group, so
    /// in-flight child runs die with it — the queue keeps their last state).
    fn campaign_kill(&mut self) {
        let Some(pid) = self.router.campaign().dispatcher_pid else {
            self.router.campaign_mut().notice =
                Some("no dispatcher was launched from this deck".to_string());
            return;
        };
        let killed = std::process::Command::new("/bin/kill")
            .args(["-9", "--", &format!("-{pid}")])
            .status();
        let deck = self.router.campaign_mut();
        match killed {
            Ok(status) if status.success() => {
                deck.dispatcher_pid = None;
                deck.notice = Some(format!("killed dispatcher process group {pid}"));
            }
            Ok(_) => deck.notice = Some(format!("process group {pid} was already gone")),
            Err(error) => deck.notice = Some(format!("kill failed: {error}")),
        }
    }

    /// Preview the selected job's seasoning prompt in the transcript. The
    /// declared-prompt editor is reserved for built-in templates; campaign
    /// seasoning files are plain per-job overrides on disk.
    fn campaign_show_prompt(&mut self) {
        let Some(target) = self.target_path_buf().cloned() else {
            return;
        };
        let Some(relative) = self
            .router
            .campaign()
            .selected_job()
            .and_then(|job| job.prompt_path.clone())
        else {
            self.router.campaign_mut().notice =
                Some("selected job has no seasoning prompt".to_string());
            return;
        };
        let path = target.join(&relative);
        match std::fs::read_to_string(&path) {
            Ok(body) => self.log_campaign_prompt(&relative, &body),
            Err(error) => {
                self.router.campaign_mut().notice =
                    Some(format!("could not read {relative}: {error}"));
            }
        }
    }

    fn log_campaign_prompt(&mut self, relative: &str, body: &str) {
        self.log(
            "campaign",
            format!("prompt {relative} ({} bytes):", body.len()),
        );
        for line in body.lines().take(20) {
            self.log("campaign", line.to_string());
        }
        if body.lines().count() > 20 {
            self.log("campaign", format!("… edit the full file at {relative}"));
        }
    }
}

/// Record a deduped trend snapshot (best effort — a history write failure
/// must not break the deck) and reload the bounded history window that
/// backs the sparkline strip.
fn refresh_trend_history(
    target: &Path,
    trend: &kuzushi_core::capabilities::campaign::trend::TrendMetrics,
) -> Vec<kuzushi_core::capabilities::campaign::trend_history::TrendSnapshot> {
    use kuzushi_core::capabilities::campaign::trend_history;
    let _ = trend_history::record_trend_snapshot(target, trend);
    trend_history::load_trend_history(target, trend_history::TREND_HISTORY_LIMIT)
}

fn load_campaign_snapshots(target: &Path) -> (Vec<CampaignSnapshot>, usize) {
    let ids = campaign_ids(target).unwrap_or_default();
    let mut snapshots = Vec::new();
    let mut unreadable = 0usize;
    for campaign_id in ids {
        match load_campaign_snapshot(target, &campaign_id) {
            Ok(snapshot) => snapshots.push(snapshot),
            Err(_) => unreadable += 1,
        }
    }
    (snapshots, unreadable)
}

fn spawn_detached_dispatcher(
    target: &Path,
    campaign_id: &str,
    args: &[String],
) -> anyhow::Result<u32> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().context("could not resolve the kuzushi binary")?;
    let logs_dir = campaign_dir(target, campaign_id).join("logs");
    std::fs::create_dir_all(&logs_dir)
        .with_context(|| format!("Could not create {}", logs_dir.display()))?;
    let log = std::fs::File::create(logs_dir.join("dispatcher.log"))
        .context("Could not open dispatcher.log")?;
    let stderr = log.try_clone().context("Could not clone dispatcher.log")?;
    let child = std::process::Command::new(exe)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(stderr)
        .process_group(0)
        .spawn()
        .context("Could not spawn the campaign dispatcher")?;
    Ok(child.id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    fn write_fixture_campaign(root: &Path) {
        let plan = serde_json::json!({
            "campaignId": "camp1",
            "tool": "sast:scan",
            "createdAtMs": 1,
            "jobs": [
                {"jobId": "j1", "tool": "sast:scan", "shard": "src/auth", "priority": 40, "input": {}},
                {"jobId": "j2", "tool": "sast:scan", "shard": "src/api", "priority": 30, "input": {}},
            ],
        });
        let plan_path =
            kuzushi_core::capabilities::campaign::campaign_plan_path(root, "camp1");
        std::fs::create_dir_all(plan_path.parent().unwrap()).unwrap();
        std::fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
        let queue = serde_json::json!({
            "jobs": { "j1": { "state": "completed", "costUsd": 0.25, "attempts": 1, "exitCode": 0 } }
        });
        let queue_path =
            kuzushi_core::capabilities::campaign::campaign_queue_path(root, "camp1");
        std::fs::write(&queue_path, serde_json::to_vec_pretty(&queue).unwrap()).unwrap();
    }

    fn deck_app() -> (tempfile::TempDir, ShellApp) {
        let temp = tempfile::tempdir().unwrap();
        write_fixture_campaign(temp.path());
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        (temp, app)
    }

    #[test]
    fn campaign_verb_opens_deck_with_folded_queue_state() {
        let (_temp, mut app) = deck_app();

        app.open_campaign_view(None);

        assert_eq!(app.shell_view(), ShellView::Campaign);
        let deck = app.router.campaign();
        assert_eq!(deck.campaigns.len(), 1);
        assert!(!deck.detail);
        let jobs = &deck.campaigns[0].jobs;
        assert_eq!(jobs[0].state, "completed");
        assert_eq!(jobs[0].cost_usd, Some(0.25));
        assert_eq!(jobs[1].state, "planned");
    }

    #[test]
    fn campaign_verb_with_id_jumps_to_detail_and_unknown_id_reports() {
        let (_temp, mut app) = deck_app();

        app.open_campaign_view(Some("camp1".to_string()));
        assert!(app.router.campaign().detail);

        app.open_campaign_view(Some("nope".to_string()));
        let deck = app.router.campaign();
        assert!(deck.notice.as_deref().unwrap_or_default().contains("nope"));
    }

    #[test]
    fn exclusion_shrinks_the_launch_scope() {
        let (_temp, mut app) = deck_app();
        app.open_campaign_view(Some("camp1".to_string()));

        app.apply_campaign_hotkey(ViewHotkeyAction::CampaignToggleExclude);

        let deck = app.router.campaign();
        assert_eq!(deck.included_job_ids(), vec!["j2".to_string()]);
    }

    #[test]
    fn deck_refresh_and_report_entry_both_fold_the_workspace_trend() {
        let (_temp, mut app) = deck_app();

        app.open_campaign_view(None);
        let trend = app.router.campaign().trend.expect("deck trend");
        assert_eq!(trend.campaign_spend_usd, 0.25);
        assert_eq!(trend.decided_findings, 0);

        // Report entry recomputes from disk without needing the deck open.
        app.router.campaign_mut().trend = None;
        app.open_report_from_current_origin();
        let trend = app.router.campaign().trend.expect("report trend");
        assert_eq!(trend.campaign_spend_usd, 0.25);
    }

    #[test]
    fn targetless_deck_reports_instead_of_substituting_cwd() {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.open_campaign_view(None);

        let deck = app.router.campaign();
        assert!(deck.campaigns.is_empty());
        assert!(deck.notice.as_deref().unwrap_or_default().contains("target"));
    }
}

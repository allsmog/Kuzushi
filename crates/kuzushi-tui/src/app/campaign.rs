//! Campaign deck behaviors: disk-snapshot refresh, cursor interaction, and
//! detached dispatcher launch and cooperative Stop. The deck never executes jobs in-process.
//! Launch spawns the matching campaign dispatcher/controller in its own
//! process group, so closing the shell never kills a campaign.

use super::state_transitions::{InputUpdate, ViewHotkeyAction};
use super::*;
use anyhow::Context;
use kuzushi_core::capabilities::campaign::campaign_dir;
use kuzushi_core::capabilities::campaign::snapshot::{
    campaign_ids, load_campaign_snapshot, CampaignSnapshot,
};
use std::path::Path;
mod dispatcher_results;
mod observations;
mod scan_progress;

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
        let Some(index) = self
            .router
            .campaign()
            .campaigns
            .iter()
            .position(|campaign| campaign.campaign_id == campaign_id)
        else {
            self.router.campaign_mut().notice = Some(format!("campaign {campaign_id:?} not found"));
            return;
        };
        let deck = self.router.campaign_mut();
        deck.selected_campaign = index;
        deck.selected_job = 0;
        deck.read_scroll = 0;
        deck.excluded.clear();
        deck.detail = true;
        deck.job_detail = false;
        deck.sync_selected_batch_workers();
        self.restore_dispatcher_failure_notice();
    }

    pub(crate) fn refresh_campaign_deck(&mut self) {
        self.collect_dispatcher_exit();
        let Some(target) = self.target_path_buf().cloned() else {
            self.router.campaign_mut().notice =
                Some("select a target to load campaigns".to_string());
            return;
        };
        self.refresh_findings_preserving_active_filter(false);
        self.refresh_phase_attempt_projection();
        let (campaigns, unreadable) = load_campaign_snapshots(&target);
        self.refresh_campaign_trend(&target, &campaigns, unreadable);
        self.replace_campaign_snapshots(campaigns, unreadable);
        self.refresh_active_batch_report();
        self.restore_dispatcher_failure_notice();
    }

    fn replace_campaign_snapshots(&mut self, campaigns: Vec<CampaignSnapshot>, unreadable: usize) {
        let deck = self.router.campaign_mut();
        deck.campaigns = campaigns;
        deck.selected_campaign = deck
            .selected_campaign
            .min(deck.campaigns.len().saturating_sub(1));
        deck.selected_job = deck.selected_job.min(deck.detail_job_ceiling());
        deck.sync_selected_batch_workers();
        deck.notice =
            (unreadable > 0).then(|| format!("{unreadable} campaign dir(s) had no readable plan"));
    }

    fn refresh_campaign_trend(
        &mut self,
        target: &Path,
        campaigns: &[CampaignSnapshot],
        unreadable: usize,
    ) {
        let spend = campaign_snapshot_spend(campaigns, unreadable);
        let trend = kuzushi_core::capabilities::campaign::trend::trend_metrics_with_spend(
            self.review_decisions(),
            spend,
        );
        let history = refresh_trend_history(target, &trend);
        let deck = self.router.campaign_mut();
        deck.trend = Some(trend);
        deck.trend_history = history;
    }

    pub(crate) fn apply_campaign_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        if self.router.campaign().batch_scan_config.is_some() {
            return self.apply_batch_scan_hotkey(action);
        }
        if action == ViewHotkeyAction::CampaignReviewStudy {
            self.review_selected_study();
            return InputUpdate::handled();
        }
        self.apply_campaign_deck_hotkey(action)
    }

    fn apply_campaign_deck_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        match action {
            ViewHotkeyAction::CampaignCursorPrevious => self.move_visible_campaign_cursor(-1),
            ViewHotkeyAction::CampaignCursorNext => self.move_visible_campaign_cursor(1),
            ViewHotkeyAction::CampaignOpenDetail => self.inspect_campaign_selection(),
            ViewHotkeyAction::CampaignOpenObservations => self.open_selected_batch_observations(),
            ViewHotkeyAction::CampaignBackToList => self.back_from_campaign_detail(),
            ViewHotkeyAction::CampaignToggleExclude => self.toggle_campaign_exclusion(),
            ViewHotkeyAction::CampaignCycleWorkers => self.cycle_campaign_workers(),
            ViewHotkeyAction::CampaignLaunch => {
                self.launch_selected_campaign();
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

    fn campaign_deck_edit(&mut self, edit: impl FnOnce(&mut CampaignRouteState)) -> InputUpdate {
        edit(self.router.campaign_mut());
        InputUpdate::handled()
    }

    fn inspect_campaign_selection(&mut self) -> InputUpdate {
        self.campaign_deck_edit(|deck| {
            deck.job_detail = deck.detail && deck.selected_job().is_some();
            deck.detail = deck.selected_campaign().is_some();
            deck.read_scroll = 0;
            deck.sync_selected_batch_workers();
        })
    }

    fn back_from_campaign_detail(&mut self) -> InputUpdate {
        if self.restore_scan_study_origin() {
            return InputUpdate::handled();
        }
        let deck = self.router.campaign_mut();
        if deck.job_detail {
            deck.job_detail = false;
            deck.read_scroll = 0;
            if let Some(offset) = crate::renderer::campaign_selection_scroll(self) {
                self.router.campaign_mut().read_scroll = offset;
            }
        } else {
            deck.detail = false;
            deck.read_scroll = 0;
        }
        InputUpdate::handled()
    }

    fn move_visible_campaign_cursor(&mut self, delta: i64) -> InputUpdate {
        let update = self.campaign_deck_edit(|deck| {
            deck.move_cursor(delta);
            if deck.job_detail {
                deck.read_scroll = 0;
            }
            deck.sync_selected_batch_workers();
        });
        self.restore_dispatcher_failure_notice();
        if let Some(offset) = crate::renderer::campaign_selection_scroll(self) {
            self.router.campaign_mut().read_scroll = offset;
        }
        update
    }

    fn cycle_campaign_workers(&mut self) -> InputUpdate {
        let deck = self.router.campaign_mut();
        let frozen = deck
            .selected_campaign()
            .filter(|campaign| super::batch_scan::is_fixed_study_snapshot(campaign))
            .map(|campaign| {
                (
                    campaign.effective_workers.unwrap_or(1),
                    campaign
                        .parallel_safety_reason
                        .clone()
                        .unwrap_or_else(|| "frozen by the study plan".to_string()),
                )
            });
        if let Some((workers, reason)) = frozen {
            deck.workers = workers;
            deck.notice = Some(format!("Study workers stay at {workers} — {reason}"));
        } else {
            deck.cycle_workers();
        }
        InputUpdate::handled()
    }

    fn toggle_campaign_exclusion(&mut self) -> InputUpdate {
        let deck = self.router.campaign_mut();
        if deck
            .selected_campaign()
            .is_some_and(super::batch_scan::is_fixed_study_snapshot)
        {
            deck.excluded.clear();
            deck.notice =
                Some("Study jobs are fixed. Prepare a new plan to change their scope.".to_string());
        } else {
            deck.toggle_selected_exclusion();
        }
        InputUpdate::handled()
    }

    /// Launch = spawn a detached dispatcher over the included job set. The
    /// deck records only the pid it spawned; dispatchers started elsewhere
    /// stay visible through queue state alone. One dispatcher per deck: a
    /// second Launch would overwrite the held child handle, orphaning the
    /// first dispatcher (unreapable, unkillable from `K`) and racing two
    /// dispatchers on the same queue.
    pub(crate) fn launch_selected_campaign(&mut self) {
        if let Some(pid) = self.deck_dispatcher_blocking_relaunch() {
            self.router.campaign_mut().notice = Some(format!(
                "dispatcher pid {pid} is still running; K requests Stop; one dispatcher per deck"
            ));
            return;
        }
        let Some((target, campaign_id, args)) = self.campaign_launch_spec() else {
            return;
        };
        let launched = self
            .check_selected_study_approval(&target, &campaign_id)
            .and_then(|()| spawn_detached_dispatcher(&target, &campaign_id, &args));
        match launched {
            Ok(child) => {
                let pid = child.id();
                self.runtime_state
                    .hold_dispatcher(child, target, campaign_id.clone());
                let deck = self.router.campaign_mut();
                deck.dispatcher_pid = Some(pid);
                deck.dispatcher_stop_requested = false;
                deck.dispatcher_failure = None;
                deck.notice = Some(format!(
                    "dispatcher pid {pid}; logs: campaigns/{campaign_id}/logs/dispatcher.log"
                ));
            }
            Err(error) => {
                self.router.campaign_mut().notice = Some(format!("launch failed: {error:#}"));
            }
        }
    }

    /// The pid blocking a relaunch, after first reaping an exited
    /// dispatcher so a finished run never blocks the next Launch.
    fn deck_dispatcher_blocking_relaunch(&mut self) -> Option<u32> {
        self.collect_dispatcher_exit();
        self.router.campaign().dispatcher_pid
    }

    fn campaign_launch_spec(&mut self) -> Option<(std::path::PathBuf, String, Vec<String>)> {
        let target = self.campaign_launch_target()?;
        let deck = self.router.campaign();
        let Some(campaign) = deck.selected_campaign() else {
            self.router.campaign_mut().notice = Some("no campaign selected".to_string());
            return None;
        };
        let campaign_id = campaign.campaign_id.clone();
        let total_jobs = campaign.jobs.len();
        let batch = is_scan_batch_snapshot(campaign);
        let included = if super::batch_scan::is_fixed_study_snapshot(campaign) {
            campaign.jobs.iter().map(|job| job.job_id.clone()).collect()
        } else {
            deck.included_job_ids()
        };
        if included.is_empty() {
            self.router.campaign_mut().notice =
                Some("every job is excluded — nothing to launch".to_string());
            return None;
        }
        let workers = campaign.effective_workers.unwrap_or(deck.workers);
        let mut args =
            campaign_process_args(batch, &campaign_id, &target, workers, &included, total_jobs);
        append_fixed_resume(&mut args, campaign);
        Some((target, campaign_id, args))
    }

    fn campaign_launch_target(&mut self) -> Option<std::path::PathBuf> {
        let Some(target) = self.target_path_buf().cloned() else {
            self.router.campaign_mut().notice = Some("launch requires a target".into());
            return None;
        };
        if self.selected_fixed_study_has_ended() {
            self.router.campaign_mut().notice = Some(
                "This fixed plan has ended. Further work requires a new approved plan.".into(),
            );
            return None;
        }
        Some(target)
    }

    pub(super) fn selected_fixed_study_has_ended(&self) -> bool {
        self.router
            .campaign()
            .selected_campaign()
            .filter(|campaign| super::batch_scan::is_fixed_study_snapshot(campaign))
            .is_some_and(|campaign| {
                !campaign
                    .jobs
                    .iter()
                    .any(|job| matches!(job.state.as_str(), "planned" | "running" | "parked"))
            })
    }

    /// Request Stop through the held child's original campaign. Keep its
    /// handle while the dispatcher settles children and saves partial work.
    fn campaign_kill(&mut self) {
        match self.runtime_state.request_dispatcher_stop() {
            Ok(pid) => {
                let deck = self.router.campaign_mut();
                deck.dispatcher_stop_requested = true;
                deck.notice = Some(format!(
                    "Stop requested for dispatcher {pid}; saving partial work"
                ));
            }
            Err(error) => {
                self.router.campaign_mut().notice = Some(format!("Stop unavailable: {error:#}"))
            }
        }
    }

    pub(crate) fn poll_campaign_completion(&mut self) -> bool {
        if !self.collect_dispatcher_exit() {
            return false;
        }
        self.refresh_campaign_deck();
        true
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

fn append_fixed_resume(args: &mut Vec<String>, campaign: &CampaignSnapshot) {
    // The batch controller validates its frozen plan and resumes eligible jobs itself.
    if is_scan_batch_snapshot(campaign) {
        return;
    }
    let paused = campaign.jobs.iter().any(|job| job.state == "parked");
    if paused && super::batch_scan::is_fixed_study_snapshot(campaign) {
        args.push("--resume".into());
    }
}

fn campaign_process_args(
    batch: bool,
    campaign_id: &str,
    target: &Path,
    workers: usize,
    included: &[String],
    total_jobs: usize,
) -> Vec<String> {
    if batch {
        return batch_controller_args(campaign_id, target);
    }
    dispatcher_args(campaign_id, target, workers, included, total_jobs)
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

fn campaign_snapshot_spend(
    campaigns: &[CampaignSnapshot],
    unreadable: usize,
) -> kuzushi_core::capabilities::campaign::trend::WorkspaceCampaignSpend {
    kuzushi_core::capabilities::campaign::trend::WorkspaceCampaignSpend {
        observed_usd: campaigns
            .iter()
            .map(|campaign| campaign.total_cost_usd)
            .sum(),
        provider_spend_unresolved: unreadable > 0
            || campaigns
                .iter()
                .any(|campaign| campaign.provider_spend_unresolved),
    }
}

/// Spawn the detached dispatcher and return its handle. Callers must keep
/// the handle and eventually reap it — dropping a std `Child` never waits,
/// which is exactly the defunct-dispatcher leak this replaces.
fn spawn_detached_dispatcher(
    target: &Path,
    campaign_id: &str,
    args: &[String],
) -> anyhow::Result<std::process::Child> {
    let exe = std::env::current_exe().context("could not resolve the kuzushi binary")?;
    let logs_dir = campaign_dir(target, campaign_id).join("logs");
    std::fs::create_dir_all(&logs_dir)
        .with_context(|| format!("Could not create {}", logs_dir.display()))?;
    let log = std::fs::File::create(logs_dir.join("dispatcher.log"))
        .context("Could not open dispatcher.log")?;
    let stderr = log.try_clone().context("Could not clone dispatcher.log")?;
    let mut command = std::process::Command::new(exe);
    configure_detached_dispatcher(&mut command);
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(stderr)
        .spawn()
        .context("Could not spawn the campaign dispatcher")
}

#[cfg(unix)]
use unix_configure_detached_dispatcher as configure_detached_dispatcher;
#[cfg(not(any(unix, windows)))]
use unsupported_platform_configure_detached_dispatcher as configure_detached_dispatcher;
#[cfg(windows)]
use windows_configure_detached_dispatcher as configure_detached_dispatcher;

#[cfg(unix)]
fn unix_configure_detached_dispatcher(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(windows)]
fn windows_configure_detached_dispatcher(command: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP);
}

#[cfg(not(any(unix, windows)))]
fn unsupported_platform_configure_detached_dispatcher(_command: &mut std::process::Command) {}

/// Group-kill a verified-live dispatcher, then reap it. `try_wait` first so
/// an already-exited dispatcher is collected without signalling anything.
#[cfg(test)]
fn kill_and_reap_dispatcher(mut child: std::process::Child, pid: u32) -> String {
    if let Ok(Some(status)) = child.try_wait() {
        return format!("dispatcher pid {pid} had already exited ({status})");
    }
    let killed = kill_dispatcher_process_tree(pid);
    if !killed.as_ref().is_ok_and(std::process::ExitStatus::success) {
        let _ = child.kill();
    }
    let _ = child.wait();
    match killed {
        Ok(status) if status.success() => format!("killed dispatcher process tree {pid}"),
        Ok(_) => format!("dispatcher process tree {pid} was already gone"),
        Err(error) => format!("kill failed: {error}"),
    }
}

#[cfg(all(test, unix))]
use unix_kill_dispatcher_process_tree as kill_dispatcher_process_tree;
#[cfg(all(test, not(any(unix, windows))))]
use unsupported_platform_kill_dispatcher_process_tree as kill_dispatcher_process_tree;
#[cfg(all(test, windows))]
use windows_kill_dispatcher_process_tree as kill_dispatcher_process_tree;

#[cfg(all(test, unix))]
fn unix_kill_dispatcher_process_tree(pid: u32) -> std::io::Result<std::process::ExitStatus> {
    std::process::Command::new("/bin/kill")
        .args(["-9", "--", &format!("-{pid}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
}

#[cfg(all(test, windows))]
fn windows_kill_dispatcher_process_tree(pid: u32) -> std::io::Result<std::process::ExitStatus> {
    std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
}

#[cfg(all(test, not(any(unix, windows))))]
fn unsupported_platform_kill_dispatcher_process_tree(
    _pid: u32,
) -> std::io::Result<std::process::ExitStatus> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process-tree termination is unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{FindingStore, Severity, V2Config};

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
        let plan_path = kuzushi_core::capabilities::campaign::campaign_plan_path(root, "camp1");
        std::fs::create_dir_all(plan_path.parent().unwrap()).unwrap();
        std::fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
        let queue = serde_json::json!({
            "jobs": { "j1": { "state": "completed", "costUsd": 0.25, "attempts": 1, "exitCode": 0 } }
        });
        let queue_path = kuzushi_core::capabilities::campaign::campaign_queue_path(root, "camp1");
        std::fs::write(&queue_path, serde_json::to_vec_pretty(&queue).unwrap()).unwrap();
    }

    pub(super) fn deck_app() -> (tempfile::TempDir, ShellApp) {
        let temp = tempfile::tempdir().unwrap();
        write_fixture_campaign(temp.path());
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        (temp, app)
    }

    fn batch_deck_app() -> (tempfile::TempDir, ShellApp) {
        let temp = tempfile::tempdir().unwrap();
        let plan = serde_json::json!({
            "kind": "scan-batch",
            "campaignId": "batch1",
            "tool": "sast:scan",
            "requestedWorkers": 6,
            "effectiveWorkers": 1,
            "parallelSafety": {"clampReason": "workspace-exclusive resource codeql"},
            "jobs": [
                {"jobId": "trial-1", "tool": "sast:scan", "priority": 1, "input": {}}
            ]
        });
        let path = kuzushi_core::capabilities::campaign::campaign_plan_path(temp.path(), "batch1");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
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
    fn paused_matrix_launch_requests_resume_without_changing_its_jobs() {
        let (_root, mut app) = deck_app();
        app.open_campaign_view(Some("camp1".into()));
        let mut campaign = app.router.campaign().selected_campaign().unwrap().clone();
        campaign.jobs[1].state = "parked".into();
        let before = campaign.jobs.clone();
        for kind in [
            kuzushi_core::capabilities::campaign::CONTEXT_MATRIX_KIND,
            kuzushi_core::capabilities::campaign::SCOPE_STUDY_KIND,
            kuzushi_core::capabilities::campaign::REVIEW_STUDY_KIND,
            "context-study",
        ] {
            campaign.kind = Some(kind.into());
            let mut args = vec!["campaign".into(), "run".into(), "camp1".into()];
            append_fixed_resume(&mut args, &campaign);
            assert!(args.contains(&"--resume".into()), "{kind}");
            assert_eq!(campaign.jobs, before);
        }
        campaign.kind = None;
        let mut legacy = vec!["campaign".into(), "run".into(), "camp1".into()];
        append_fixed_resume(&mut legacy, &campaign);
        assert!(!legacy.contains(&"--resume".into()));
    }

    #[test]
    fn paused_scan_batch_launch_uses_its_controller_without_a_resume_flag() {
        let (_root, mut app) = deck_app();
        app.open_campaign_view(Some("camp1".into()));
        let campaign = &mut app.router.campaign_mut().campaigns[0];
        campaign.kind = Some(kuzushi_core::capabilities::campaign::SCAN_BATCH_KIND.into());
        campaign.jobs[1].state = "parked".into();
        let before = campaign.jobs.clone();
        let (target, id, args) = app.campaign_launch_spec().unwrap();
        assert_eq!(args, batch_controller_args(&id, &target));
        assert!(!args.contains(&"--resume".into()));
        assert_eq!(app.router.campaign().campaigns[0].jobs, before);
    }

    #[test]
    fn settled_fixed_studies_refuse_launch_without_changing_consumed_jobs() {
        let (_root, mut app) = deck_app();
        app.open_campaign_view(Some("camp1".into()));
        for kind in [
            kuzushi_core::capabilities::campaign::SCAN_BATCH_KIND,
            kuzushi_core::capabilities::campaign::CONTEXT_MATRIX_KIND,
            kuzushi_core::capabilities::campaign::SCOPE_STUDY_KIND,
            kuzushi_core::capabilities::campaign::REVIEW_STUDY_KIND,
            "context-study",
        ] {
            for state in ["completed", "failed"] {
                let campaign = &mut app.router.campaign_mut().campaigns[0];
                campaign.kind = Some(kind.into());
                for job in &mut campaign.jobs {
                    job.state = state.into();
                    job.attempts = 1;
                }
                let before = campaign.jobs.clone();
                assert!(app.campaign_launch_spec().is_none(), "{kind}/{state}");
                let binding = app
                    .view_keybindings_for_view(ShellView::Campaign)
                    .into_iter()
                    .find(|binding| binding.action == ViewHotkeyAction::CampaignLaunch)
                    .unwrap();
                assert_eq!(binding.label, "new plan required");
                assert_eq!(app.router.campaign().campaigns[0].jobs, before);
                assert!(app
                    .router
                    .campaign()
                    .notice
                    .as_deref()
                    .unwrap()
                    .contains("new approved plan"));
            }
            for state in ["planned", "running", "parked"] {
                app.router.campaign_mut().campaigns[0].jobs[0].state = state.into();
                assert!(app.campaign_launch_spec().is_some(), "{kind}/{state}");
            }
        }
        app.router.campaign_mut().campaigns[0].kind = None;
        for job in &mut app.router.campaign_mut().campaigns[0].jobs {
            job.state = "completed".into();
        }
        assert!(
            app.campaign_launch_spec().is_some(),
            "legacy behavior is preserved"
        );
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
    fn batch_trials_cannot_be_excluded() {
        let (_temp, mut app) = batch_deck_app();
        app.open_campaign_view(Some("batch1".to_string()));

        app.apply_campaign_hotkey(ViewHotkeyAction::CampaignToggleExclude);

        assert!(app.router.campaign().excluded.is_empty());
        assert!(
            app.router
                .campaign()
                .notice
                .as_deref()
                .is_some_and(
                    |notice| notice.contains("jobs are fixed") && notice.contains("new plan")
                )
        );
    }

    #[test]
    fn batch_reopen_freezes_workers_and_relaunch_uses_the_controller() {
        let (_temp, mut app) = batch_deck_app();
        app.open_campaign_view(Some("batch1".to_string()));

        assert_eq!(app.router.campaign().workers, 1);
        app.apply_campaign_hotkey(ViewHotkeyAction::CampaignCycleWorkers);
        assert_eq!(app.router.campaign().workers, 1);
        assert!(app
            .router
            .campaign()
            .notice
            .as_deref()
            .is_some_and(|notice| notice.contains("codeql")));

        app.router.campaign_mut().workers = 8;
        let (_, _, args) = app.campaign_launch_spec().unwrap();
        assert_eq!(
            args,
            [
                "--plain",
                "--target",
                _temp.path().canonicalize().unwrap().to_str().unwrap(),
                "campaign",
                "batch",
                "batch1"
            ]
        );
    }

    #[test]
    fn campaign_refresh_loads_detached_findings_without_changing_projection() {
        let (temp, mut app) = deck_app();
        app.open_campaign_view(None);
        app.refresh_findings_filtered("rank:high");
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("detached-run", workspace.root(), "running")
            .unwrap();
        for (rule, severity) in [("high", Severity::High), ("low", Severity::Low)] {
            let finding = Finding::new_semgrep(rule, "src/main.rs", 1, None, severity, rule);
            store.insert_finding("detached-run", &finding).unwrap();
        }
        app.set_input("preserve this draft");
        let origin = app.shell_view();

        app.refresh_campaign_deck();

        assert_eq!(app.active_findings_filter().as_deref(), Some("rank:high"));
        assert_eq!(app.findings().len(), 1);
        assert_eq!(app.domain().finding_ledger_counts().unwrap().total, 2);
        assert_eq!(app.shell_view(), origin);
        assert_eq!(app.input(), "preserve this draft");
    }

    #[test]
    fn campaign_refresh_recovers_external_scan_result_without_selecting_or_stealing_focus() {
        use kuzushi_core::run_artifacts::{
            record_tool_run_complete, record_tool_run_started, ToolRunRecord,
        };
        use kuzushi_core::workflow_attempts::{
            append_phase_attempt_completed_with_v2, PhaseAttemptCompleted, PhaseAttemptOutcome,
            PhaseTargetSnapshot,
        };
        let (temp, mut app) = deck_app();
        app.open_campaign_view(None);
        let record = ToolRunRecord::new(temp.path(), "external-discovery", "tool", "sast:scan");
        record_tool_run_started(record, &serde_json::json!({}));
        record_tool_run_complete(
            record,
            &serde_json::json!({"ok":true,"data":{"fixture":"phase refresh only"}}),
        );
        let completed = PhaseAttemptCompleted::new(
            WorkflowPhase::Scan,
            vec!["external-discovery".into()],
            PhaseTargetSnapshot::capture(temp.path()),
            PhaseAttemptOutcome::Completed,
        )
        .with_attempt_id(kuzushi_core::run_lifecycle::RunAttemptId::new().to_string());
        append_phase_attempt_completed_with_v2(temp.path(), completed).unwrap();
        app.set_input("held draft");
        app.router.campaign_mut().read_scroll = 8;

        app.refresh_campaign_deck();

        assert!(app
            .engagement
            .unresolved_phase_attempt(WorkflowPhase::Scan)
            .is_some());
        assert!(app
            .engagement
            .selected_phase_attempt(WorkflowPhase::Scan)
            .is_none());
        assert_eq!(app.shell_view(), ShellView::Campaign);
        assert_eq!(app.input(), "held draft");
        assert_eq!(app.router.campaign().read_scroll, 8);
    }

    #[test]
    fn deck_refresh_folds_campaign_spend_and_report_entry_keeps_it_separate() {
        let (_temp, mut app) = deck_app();

        app.open_campaign_view(None);
        let trend = app.router.campaign().trend.expect("deck trend");
        assert_eq!(trend.campaign_spend_usd, 0.25);
        assert_eq!(trend.decided_findings, 0);

        // Report uses asynchronously hydrated run records. Opening it must
        // not promote campaign-only spend to a workspace total or write trend history.
        app.router.campaign_mut().trend = None;
        let history = app.router.campaign().trend_history.clone();
        app.open_report_from_current_origin();
        assert!(app.router.campaign().trend.is_none());
        assert_eq!(app.router.campaign().trend_history, history);
        assert_eq!(app.shell_view(), ShellView::Report);
    }

    #[cfg(unix)]
    #[test]
    fn kill_and_reap_collects_a_live_dispatcher_without_leaving_a_zombie() {
        use std::os::unix::process::CommandExt;
        let child = std::process::Command::new("/bin/sleep")
            .arg("10")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let started = std::time::Instant::now();

        let notice = kill_and_reap_dispatcher(child, pid);

        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "dispatcher process tree was not terminated promptly"
        );
        assert!(
            notice.contains("killed dispatcher process tree"),
            "{notice}"
        );
        // Reaped: the pid slot is free or at least no longer our zombie.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        assert!(
            stat.is_err() || !stat.unwrap().contains(") Z "),
            "dispatcher {pid} left a zombie"
        );
    }

    #[cfg(unix)]
    #[test]
    fn kill_and_reap_falls_back_when_the_process_group_is_missing() {
        let child = std::process::Command::new("/bin/sleep")
            .arg("10")
            .spawn()
            .unwrap();
        let pid = child.id();
        let started = std::time::Instant::now();

        let notice = kill_and_reap_dispatcher(child, pid);

        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "direct child termination did not replace the missing group kill"
        );
        assert!(notice.contains("already gone"), "{notice}");
    }

    #[cfg(unix)]
    #[test]
    fn detached_dispatcher_starts_in_its_own_process_group() {
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("10");
        configure_detached_dispatcher(&mut command);
        let child = command.spawn().unwrap();
        let pid = child.id();
        let output = std::process::Command::new("/bin/ps")
            .args(["-o", "pgid=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        let process_group: u32 = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();

        let _ = kill_and_reap_dispatcher(child, pid);

        assert_eq!(process_group, pid);
    }

    #[test]
    fn kill_and_reap_reports_an_already_exited_dispatcher() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let notice = kill_and_reap_dispatcher(child, pid);

        assert!(notice.contains("already exited"), "{notice}");
    }

    #[test]
    fn deck_refresh_reaps_an_exited_dispatcher_and_clears_its_pid() {
        let (_temp, mut app) = deck_app();
        let child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        app.runtime_state.set_dispatcher_child(Some(child));
        app.router.campaign_mut().dispatcher_pid = Some(pid);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            app.refresh_campaign_deck();
            if app.router.campaign().dispatcher_pid.is_none() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "exited dispatcher was never reaped"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        assert!(
            stat.is_err() || !stat.unwrap().contains(") Z "),
            "dispatcher {pid} left a zombie"
        );
    }

    /// A second Launch while the deck's dispatcher runs would overwrite the
    /// held child handle: the first dispatcher becomes unreapable and `K`
    /// can no longer kill it. Launch must refuse instead.
    #[cfg(unix)]
    #[test]
    fn launch_refuses_while_the_deck_dispatcher_is_still_running() {
        let (_temp, mut app) = deck_app();
        use std::os::unix::process::CommandExt;
        let child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        app.runtime_state.set_dispatcher_child(Some(child));
        app.router.campaign_mut().dispatcher_pid = Some(pid);

        app.apply_campaign_hotkey(ViewHotkeyAction::CampaignLaunch);

        let deck = app.router.campaign();
        assert_eq!(deck.dispatcher_pid, Some(pid), "pid must not be replaced");
        let notice = deck.notice.as_deref().unwrap_or_default();
        assert!(notice.contains("still running"), "{notice}");
        // The held handle still belongs to the first dispatcher; clean up.
        let held = app
            .runtime_state
            .take_dispatcher_child()
            .expect("handle kept");
        assert_eq!(held.id(), pid, "handle must not be replaced");
        kill_and_reap_dispatcher(held, pid);
    }

    #[test]
    fn an_exited_dispatcher_never_blocks_the_next_launch() {
        let (_temp, mut app) = deck_app();
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        app.runtime_state.set_dispatcher_child(Some(child));
        app.router.campaign_mut().dispatcher_pid = Some(pid);

        assert_eq!(app.deck_dispatcher_blocking_relaunch(), None);
        assert_eq!(app.router.campaign().dispatcher_pid, None);
    }

    #[test]
    fn targetless_deck_reports_instead_of_substituting_cwd() {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.open_campaign_view(None);

        let deck = app.router.campaign();
        assert!(deck.campaigns.is_empty());
        assert!(deck
            .notice
            .as_deref()
            .unwrap_or_default()
            .contains("target"));
    }
}

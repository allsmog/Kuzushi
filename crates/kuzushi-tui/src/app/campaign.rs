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
        if self.runtime_state.reap_exited_dispatcher() {
            self.router.campaign_mut().dispatcher_pid = None;
        }
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
        deck.notice =
            (unreadable > 0).then(|| format!("{unreadable} campaign dir(s) had no readable plan"));
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

    fn campaign_deck_edit(&mut self, edit: impl FnOnce(&mut CampaignRouteState)) -> InputUpdate {
        edit(self.router.campaign_mut());
        InputUpdate::handled()
    }

    /// Launch = spawn a detached dispatcher over the included job set. The
    /// deck records only the pid it spawned; dispatchers started elsewhere
    /// stay visible through queue state alone. One dispatcher per deck: a
    /// second Launch would overwrite the held child handle, orphaning the
    /// first dispatcher (unreapable, unkillable from `K`) and racing two
    /// dispatchers on the same queue.
    fn campaign_launch(&mut self) {
        if let Some(pid) = self.deck_dispatcher_blocking_relaunch() {
            self.router.campaign_mut().notice = Some(format!(
                "dispatcher pid {pid} is still running — K kills it; one dispatcher per deck"
            ));
            return;
        }
        let Some((target, campaign_id, args)) = self.campaign_launch_spec() else {
            return;
        };
        match spawn_detached_dispatcher(&target, &campaign_id, &args) {
            Ok(child) => {
                let pid = child.id();
                self.runtime_state.set_dispatcher_child(Some(child));
                let deck = self.router.campaign_mut();
                deck.dispatcher_pid = Some(pid);
                deck.notice = Some(format!(
                    "dispatcher pid {pid} — logs: campaigns/{campaign_id}/logs/dispatcher.log"
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
        if self.runtime_state.reap_exited_dispatcher() {
            self.router.campaign_mut().dispatcher_pid = None;
        }
        self.router.campaign().dispatcher_pid
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
    /// The held child handle proves the pid still belongs to our dispatcher
    /// (an un-reaped child's pid cannot be recycled) and is reaped afterward
    /// so no zombie survives.
    fn campaign_kill(&mut self) {
        let Some(pid) = self.router.campaign().dispatcher_pid else {
            self.router.campaign_mut().notice =
                Some("no dispatcher was launched from this deck".to_string());
            return;
        };
        let notice = match self.runtime_state.take_dispatcher_child() {
            Some(child) => kill_and_reap_dispatcher(child, pid),
            None => format!(
                "dispatcher pid {pid} has no live handle — refusing to kill a possibly \
                 recycled pid; stop it manually if it still runs"
            ),
        };
        let deck = self.router.campaign_mut();
        deck.dispatcher_pid = None;
        deck.notice = Some(notice);
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

/// Spawn the detached dispatcher and return its handle. Callers must keep
/// the handle and eventually reap it — dropping a std `Child` never waits,
/// which is exactly the defunct-dispatcher leak this replaces.
fn spawn_detached_dispatcher(
    target: &Path,
    campaign_id: &str,
    args: &[String],
) -> anyhow::Result<std::process::Child> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().context("could not resolve the kuzushi binary")?;
    let logs_dir = campaign_dir(target, campaign_id).join("logs");
    std::fs::create_dir_all(&logs_dir)
        .with_context(|| format!("Could not create {}", logs_dir.display()))?;
    let log = std::fs::File::create(logs_dir.join("dispatcher.log"))
        .context("Could not open dispatcher.log")?;
    let stderr = log.try_clone().context("Could not clone dispatcher.log")?;
    std::process::Command::new(exe)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(stderr)
        .process_group(0)
        .spawn()
        .context("Could not spawn the campaign dispatcher")
}

/// Group-kill a verified-live dispatcher, then reap it. `try_wait` first so
/// an already-exited dispatcher is collected without signalling anything.
fn kill_and_reap_dispatcher(mut child: std::process::Child, pid: u32) -> String {
    if let Ok(Some(status)) = child.try_wait() {
        return format!("dispatcher pid {pid} had already exited ({status})");
    }
    let killed = std::process::Command::new("/bin/kill")
        .args(["-9", "--", &format!("-{pid}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = child.wait();
    match killed {
        Ok(status) if status.success() => format!("killed dispatcher process group {pid}"),
        Ok(_) => format!("process group {pid} was already gone"),
        Err(error) => format!("kill failed: {error}"),
    }
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
        let plan_path = kuzushi_core::capabilities::campaign::campaign_plan_path(root, "camp1");
        std::fs::create_dir_all(plan_path.parent().unwrap()).unwrap();
        std::fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
        let queue = serde_json::json!({
            "jobs": { "j1": { "state": "completed", "costUsd": 0.25, "attempts": 1, "exitCode": 0 } }
        });
        let queue_path = kuzushi_core::capabilities::campaign::campaign_queue_path(root, "camp1");
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
    fn kill_and_reap_collects_a_live_dispatcher_without_leaving_a_zombie() {
        use std::os::unix::process::CommandExt;
        let child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();

        let notice = kill_and_reap_dispatcher(child, pid);

        assert!(
            notice.contains("killed dispatcher process group"),
            "{notice}"
        );
        // Reaped: the pid slot is free or at least no longer our zombie.
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
        assert!(
            stat.is_err() || !stat.unwrap().contains(") Z "),
            "dispatcher {pid} left a zombie"
        );
    }

    #[test]
    fn kill_and_reap_reports_an_already_exited_dispatcher() {
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
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
        let child = std::process::Command::new("/bin/true").spawn().unwrap();
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
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
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

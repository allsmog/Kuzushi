use super::*;
use kuzushi_core::incremental_index::{coalesce_changes, LiveWorkspaceWatcher, WorkspaceChange};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    Arc,
};
use std::time::{Duration, Instant};

const WATCHER_EVENT_CHANNEL_CAPACITY: usize = 4096;
const WATCHER_DRAIN_LIMIT: usize = 256;
const STATE_ARTIFACT_DEBOUNCE: Duration = Duration::from_millis(150);
const STATE_ARTIFACT_REFRESH_COOLDOWN: Duration = Duration::from_secs(2);

pub(crate) struct WorkspaceWatcherRuntime {
    target: PathBuf,
    watcher: WatcherHandle,
    rx: Receiver<WorkspaceWatcherBatch>,
    overflowed: Arc<AtomicBool>,
    deferred_state_artifact_paths: Vec<PathBuf>,
    state_artifact_flush_after: Option<Instant>,
    last_state_artifact_flush: Option<Instant>,
}

/// Recursive watch registration walks every directory under the target —
/// minutes on monorepo-scale trees — so the handle arrives asynchronously.
/// `Failed` degrades to an unwatched shell instead of aborting it.
enum WatcherHandle {
    Registering(Receiver<Result<LiveWorkspaceWatcher>>),
    Ready { _keep_alive: LiveWorkspaceWatcher },
    Failed,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct WatcherMessageOutcome {
    pub(crate) changed: bool,
    pub(crate) tail_may_remain: bool,
}

impl WorkspaceWatcherRuntime {
    pub(crate) fn start(target: Option<&Path>, wake: TerminalLoopWake) -> Result<Option<Self>> {
        let Some(target) = target else {
            return Ok(None);
        };
        let (tx, rx) = mpsc::sync_channel(WATCHER_EVENT_CHANNEL_CAPACITY);
        let overflowed = Arc::new(AtomicBool::new(false));
        let watcher = spawn_watch_registration(
            target.to_path_buf(),
            watcher_sink(tx, overflowed.clone(), wake.clone()),
            wake,
        )?;
        Ok(Some(Self {
            target: target.to_path_buf(),
            watcher,
            rx,
            overflowed,
            deferred_state_artifact_paths: Vec::new(),
            state_artifact_flush_after: None,
            last_state_artifact_flush: None,
        }))
    }

    fn watches(&self, target: &Path) -> bool {
        self.target == target
    }

    /// Adopt the watcher handle once background registration settles. Writes
    /// that landed while the walk was still registering subtrees were never
    /// observed, so settling (success or failure) surfaces one overflow
    /// refresh to close that gap.
    fn adopt_watch_registration(&mut self) {
        let WatcherHandle::Registering(ready) = &self.watcher else {
            return;
        };
        let settled = match ready.try_recv() {
            Err(TryRecvError::Empty) => return,
            Ok(Ok(watcher)) => WatcherHandle::Ready {
                _keep_alive: watcher,
            },
            Ok(Err(_)) | Err(TryRecvError::Disconnected) => WatcherHandle::Failed,
        };
        self.overflowed.store(true, Ordering::SeqCst);
        self.watcher = settled;
    }

    fn drain_changes(&mut self, release_deferred_state: bool) -> WatcherDrainOutcome {
        self.adopt_watch_registration();
        let mut outcome = self.collect_pending_changes(release_deferred_state);
        let new_state_event = outcome.new_state_event;
        let drained = &mut outcome.batch;
        drained.changes = coalesce_changes(std::mem::take(&mut drained.changes));
        drained.state_artifact_paths.sort();
        drained.state_artifact_paths.dedup();
        self.debounce_state_artifacts(drained, new_state_event);
        outcome
    }

    fn collect_pending_changes(&mut self, release_deferred_state: bool) -> WatcherDrainOutcome {
        let mut drained = overflow_marker(&self.overflowed);
        let mut new_state_event = !drained.state_artifact_paths.is_empty();
        let mut tail_may_remain = true;
        if release_deferred_state {
            drained
                .state_artifact_paths
                .append(&mut self.deferred_state_artifact_paths);
        }
        for _ in 0..WATCHER_DRAIN_LIMIT {
            match self.rx.try_recv() {
                Ok(batch) => {
                    new_state_event |= !batch.state_artifact_paths.is_empty();
                    drained.merge(batch);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => {
                    tail_may_remain = false;
                    break;
                }
            }
        }
        WatcherDrainOutcome {
            batch: drained,
            new_state_event,
            tail_may_remain,
        }
    }

    fn debounce_state_artifacts(
        &mut self,
        drained: &mut WorkspaceWatcherBatch,
        new_state_event: bool,
    ) {
        // Arm the quiet-window deadline once per deferral cycle. Re-arming
        // on every drained event lets a sustained writer (sub-debounce
        // cadence, e.g. a campaign fleet) move the deadline forever — the
        // refresh then starves until the writer exits and the shell shows
        // stale findings for the campaign's whole lifetime. One fixed
        // deadline bounds staleness at debounce + cooldown.
        if new_state_event && self.state_artifact_flush_after.is_none() {
            self.state_artifact_flush_after = Some(Instant::now() + STATE_ARTIFACT_DEBOUNCE);
        }
        if self.state_artifact_flush_blocked() {
            self.defer_state_artifact_paths(std::mem::take(&mut drained.state_artifact_paths));
            return;
        }
        self.state_artifact_flush_after = None;
        if !drained.state_artifact_paths.is_empty() {
            self.last_state_artifact_flush = Some(Instant::now());
        }
    }

    /// A steady writer — most often Kuzushi's own background store writes —
    /// must not re-trigger the full external-state refresh (hydration
    /// restart, scope-tree reload, findings reload) on every event burst.
    /// Flushes wait for a quiet debounce window, then hold a cooldown
    /// between applied refreshes.
    fn state_artifact_flush_blocked(&self) -> bool {
        let now = Instant::now();
        self.state_artifact_flush_after
            .is_some_and(|deadline| deadline > now)
            || self
                .last_state_artifact_flush
                .is_some_and(|flushed| now < flushed + STATE_ARTIFACT_REFRESH_COOLDOWN)
    }

    fn defer_state_artifact_paths(&mut self, mut paths: Vec<PathBuf>) {
        self.deferred_state_artifact_paths.append(&mut paths);
        self.deferred_state_artifact_paths.sort();
        self.deferred_state_artifact_paths.dedup();
    }
}

struct WatcherDrainOutcome {
    batch: WorkspaceWatcherBatch,
    new_state_event: bool,
    tail_may_remain: bool,
}

#[derive(Default)]
struct WorkspaceWatcherBatch {
    changes: Vec<WorkspaceChange>,
    state_artifact_paths: Vec<PathBuf>,
}

impl WorkspaceWatcherBatch {
    fn merge(&mut self, other: Self) {
        self.changes.extend(other.changes);
        self.state_artifact_paths.extend(other.state_artifact_paths);
    }

    fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.state_artifact_paths.is_empty()
    }
}

pub(crate) fn reconcile_workspace_watcher(
    current: &mut Option<WorkspaceWatcherRuntime>,
    target: Option<&Path>,
    wake: TerminalLoopWake,
) -> Result<bool> {
    if watcher_matches_target(current.as_ref(), target) {
        return Ok(false);
    }
    *current = WorkspaceWatcherRuntime::start(target, wake)?;
    Ok(true)
}

fn watcher_matches_target(
    current: Option<&WorkspaceWatcherRuntime>,
    target: Option<&Path>,
) -> bool {
    match (current, target) {
        (None, None) => true,
        (Some(watcher), Some(target)) => watcher.watches(target),
        (None, Some(_)) | (Some(_), None) => false,
    }
}

pub(crate) fn apply_watcher_messages_with_outcome(
    app: &mut ShellApp,
    watcher: Option<&mut WorkspaceWatcherRuntime>,
) -> WatcherMessageOutcome {
    let Some(watcher) = watcher else {
        return WatcherMessageOutcome::default();
    };
    let work_running = app.has_running_work();
    let drained = watcher.drain_changes(!work_running);
    let batch = drained.batch;
    if batch.is_empty() {
        return WatcherMessageOutcome {
            changed: false,
            tail_may_remain: drained.tail_may_remain,
        };
    }
    // External writers changed the workspace: even when the refresh is
    // deferred/debounced, the liveness badge must stop claiming "idle".
    app.ui_mut().record_external_sync(Instant::now());
    let source_changed = !batch.changes.is_empty()
        && update_and_execute_effects(app, Msg::WorkspaceChanged(batch.changes));
    let state_changed = if batch.state_artifact_paths.is_empty() {
        false
    } else if work_running {
        watcher.defer_state_artifact_paths(batch.state_artifact_paths);
        false
    } else {
        let effects = app.apply_external_workspace_state_change(&batch.state_artifact_paths);
        EffectRuntime::execute(app, effects);
        true
    };
    WatcherMessageOutcome {
        changed: source_changed || state_changed,
        tail_may_remain: drained.tail_may_remain,
    }
}

/// Registering the recursive watch must not run on the shell thread: the
/// directory walk blocks for minutes on large targets and input would be
/// dead until it finishes. Events flow through `sink` as subtrees register;
/// the handle is delivered for adoption on a later drain.
fn spawn_watch_registration(
    target: PathBuf,
    sink: impl FnMut(Vec<WorkspaceChange>, Vec<PathBuf>) + Send + 'static,
    wake: TerminalLoopWake,
) -> Result<WatcherHandle> {
    let (ready_tx, ready_rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("kz-watch-register".into())
        .spawn(move || {
            let result = LiveWorkspaceWatcher::start_with_state_events(&target, sink);
            let _ = ready_tx.send(result);
            wake.notify();
        })
        .context("could not spawn watch registration")?;
    Ok(WatcherHandle::Registering(ready_rx))
}

fn watcher_sink(
    tx: SyncSender<WorkspaceWatcherBatch>,
    overflowed: Arc<AtomicBool>,
    wake: TerminalLoopWake,
) -> impl FnMut(Vec<WorkspaceChange>, Vec<PathBuf>) + Send + 'static {
    move |changes, state_artifact_paths| {
        if send_watcher_changes(&tx, changes, state_artifact_paths, &overflowed) {
            wake.notify();
        }
    }
}

fn send_watcher_changes(
    tx: &SyncSender<WorkspaceWatcherBatch>,
    changes: Vec<WorkspaceChange>,
    state_artifact_paths: Vec<PathBuf>,
    overflowed: &AtomicBool,
) -> bool {
    if changes.is_empty() && state_artifact_paths.is_empty() {
        return false;
    }
    match tx.try_send(WorkspaceWatcherBatch {
        changes,
        state_artifact_paths,
    }) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            overflowed.store(true, Ordering::SeqCst);
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

fn overflow_marker(overflowed: &AtomicBool) -> WorkspaceWatcherBatch {
    if overflowed.swap(false, Ordering::SeqCst) {
        WorkspaceWatcherBatch {
            changes: vec![WorkspaceChange::GitHeadChanged],
            state_artifact_paths: vec![PathBuf::from(".kuzushi/v3")],
        }
    } else {
        WorkspaceWatcherBatch::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{incremental_index::ReindexPlan, V2Config};

    #[test]
    fn watcher_messages_apply_workspace_stale_state() {
        let (input, wake) = TerminalLoopInbox::channel_for_test();
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut watcher = watcher_for_test(wake);

        watcher
            .tx
            .try_send(WorkspaceWatcherBatch {
                changes: vec![WorkspaceChange::FileChanged("src/routes/a.rs".into())],
                state_artifact_paths: Vec::new(),
            })
            .unwrap();

        assert!(apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed);
        assert!(input
            .recv_timeout(Duration::from_millis(0))
            .unwrap()
            .is_none());
        assert_eq!(
            app.workspace_stale().unwrap().strongest_plan(),
            ReindexPlan::FileFactsAndLocalAttackSurface
        );
        // The liveness badge must report the external writer, not "idle".
        assert_eq!(
            crate::ui_view_models::work_liveness(&app),
            crate::ui_view_models::WorkLiveness::ExternalSync
        );
    }

    #[test]
    fn watcher_overflow_marks_snapshot_stale() {
        let (_input, wake) = TerminalLoopInbox::channel_for_test();
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut watcher = watcher_for_test(wake);
        watcher.runtime.overflowed.store(true, Ordering::SeqCst);

        assert!(apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed);

        assert_eq!(
            app.workspace_stale().unwrap().strongest_plan(),
            ReindexPlan::FullSnapshot
        );
    }

    #[test]
    fn capped_watcher_drain_rearms_the_remaining_tail() {
        let (input, wake) = TerminalLoopInbox::channel_for_test();
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut watcher = watcher_for_test(wake.clone());
        for index in 0..=WATCHER_DRAIN_LIMIT {
            watcher
                .tx
                .try_send(WorkspaceWatcherBatch {
                    changes: vec![WorkspaceChange::FileChanged(
                        format!("src/file-{index}.rs").into(),
                    )],
                    state_artifact_paths: Vec::new(),
                })
                .unwrap();
        }
        wake.notify();
        assert!(matches!(
            input.recv_timeout(Duration::ZERO).unwrap(),
            Some(TerminalLoopEvent::Wake)
        ));

        let first = apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime));
        rearm_work_tail(&wake, first.tail_may_remain);

        assert!(first.changed);
        assert!(first.tail_may_remain);
        assert!(matches!(
            input.recv_timeout(Duration::ZERO).unwrap(),
            Some(TerminalLoopEvent::Wake)
        ));
        let second = apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime));
        assert!(second.changed);
        assert!(!second.tail_may_remain);
    }

    #[test]
    fn runtime_state_event_invalidates_cached_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        workspace.ensure_state_dir().unwrap();
        let artifact = workspace.state_dir().join("external.json");
        std::fs::write(&artifact, r#"{"value":"before"}"#).unwrap();
        let (_input, wake) = TerminalLoopInbox::channel_for_test();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        let mut watcher = watcher_for_test(wake);
        assert!(matches!(
            app.workbench_cache().borrow_mut().json_file(&artifact),
            JsonFileState::Present(_)
        ));
        std::fs::write(&artifact, r#"{"value":"after"}"#).unwrap();
        watcher
            .tx
            .try_send(WorkspaceWatcherBatch {
                changes: Vec::new(),
                state_artifact_paths: vec![PathBuf::from(".kuzushi/v3/external.json")],
            })
            .unwrap();

        let debounced = watcher.runtime.drain_changes(true);
        assert!(debounced.batch.state_artifact_paths.is_empty());
        std::thread::sleep(STATE_ARTIFACT_DEBOUNCE + Duration::from_millis(10));
        assert!(apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed);
        let refreshed = app.workbench_cache().borrow_mut().json_file(&artifact);
        assert!(matches!(
            refreshed,
            JsonFileState::Present(value) if value["value"] == "after"
        ));
    }

    /// Bounded refresh under a write burst: hundreds of state-artifact
    /// batches from an external writer must fold into exactly ONE applied
    /// refresh once the debounce window closes — not one refresh per event.
    #[test]
    fn state_event_burst_folds_into_a_single_debounced_refresh() {
        let (_input, wake) = TerminalLoopInbox::channel_for_test();
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut watcher = watcher_for_test(wake);
        for _ in 0..500 {
            watcher
                .tx
                .try_send(WorkspaceWatcherBatch {
                    changes: Vec::new(),
                    state_artifact_paths: vec![PathBuf::from(
                        ".kuzushi/v3/campaigns/camp/queue.json",
                    )],
                })
                .unwrap();
        }
        // Drain the whole burst the way the terminal loop would: every
        // in-window drain defers (no refresh applied).
        loop {
            let outcome =
                apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime));
            assert!(!outcome.changed, "refresh applied inside debounce window");
            if !outcome.tail_may_remain {
                break;
            }
        }

        std::thread::sleep(STATE_ARTIFACT_DEBOUNCE + Duration::from_millis(20));
        let settled = apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime));
        assert!(settled.changed, "the burst must apply exactly one refresh");
        let after = apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime));
        assert!(!after.changed, "no residual refresh work may remain");
    }

    /// A writer that keeps producing state events after one applied refresh
    /// must wait out the refresh cooldown instead of re-triggering the full
    /// external-state refresh every debounce window.
    #[test]
    fn state_refresh_holds_a_cooldown_between_applied_flushes() {
        let (_input, wake) = TerminalLoopInbox::channel_for_test();
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut watcher = watcher_for_test(wake);
        let send_state_event = |watcher: &TestWatcherRuntime| {
            watcher
                .tx
                .try_send(WorkspaceWatcherBatch {
                    changes: Vec::new(),
                    state_artifact_paths: vec![PathBuf::from(".kuzushi/v3/index.sqlite3")],
                })
                .unwrap();
        };

        send_state_event(&watcher);
        assert!(!apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed);
        std::thread::sleep(STATE_ARTIFACT_DEBOUNCE + Duration::from_millis(10));
        assert!(
            apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed,
            "the first quiet window must apply a refresh"
        );

        send_state_event(&watcher);
        assert!(!apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed);
        std::thread::sleep(STATE_ARTIFACT_DEBOUNCE + Duration::from_millis(10));
        assert!(
            !apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed,
            "a flush inside the refresh cooldown must stay deferred"
        );

        watcher.runtime.last_state_artifact_flush =
            Some(Instant::now() - STATE_ARTIFACT_REFRESH_COOLDOWN);
        assert!(
            apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed,
            "the deferred paths must apply once the cooldown expires"
        );
    }

    /// `start` must return without waiting for the recursive watch walk —
    /// a blocking walk deafens the shell to input for minutes on large
    /// targets. The handle is adopted on a later drain, and settling
    /// surfaces exactly one overflow refresh to cover the unwatched gap.
    #[test]
    fn start_returns_immediately_and_adopts_the_registration_later() {
        let tmp = tempfile::tempdir().unwrap();
        let (_input, wake) = TerminalLoopInbox::channel_for_test();
        let mut runtime = WorkspaceWatcherRuntime::start(Some(tmp.path()), wake)
            .unwrap()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        while matches!(runtime.watcher, WatcherHandle::Registering(_)) {
            assert!(Instant::now() < deadline, "registration never settled");
            runtime.adopt_watch_registration();
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(matches!(runtime.watcher, WatcherHandle::Ready { .. }));
        let refresh = runtime.drain_changes(true);
        assert_eq!(
            refresh.batch.changes,
            vec![WorkspaceChange::GitHeadChanged],
            "settling must surface the overflow refresh"
        );
        assert!(runtime.drain_changes(true).batch.changes.is_empty());
    }

    /// A registration thread that dies (unreadable root, inotify limits)
    /// degrades to an unwatched shell with one overflow refresh — it must
    /// not abort the shell or wedge the drain path.
    #[test]
    fn failed_registration_degrades_instead_of_aborting() {
        let (_input, wake) = TerminalLoopInbox::channel_for_test();
        let mut watcher = watcher_for_test(wake);
        let (ready_tx, ready_rx) = mpsc::channel::<Result<LiveWorkspaceWatcher>>();
        watcher.runtime.watcher = WatcherHandle::Registering(ready_rx);
        drop(ready_tx);

        let refresh = watcher.runtime.drain_changes(true);

        assert!(matches!(watcher.runtime.watcher, WatcherHandle::Failed));
        assert_eq!(refresh.batch.changes, vec![WorkspaceChange::GitHeadChanged]);
        assert!(watcher.runtime.drain_changes(true).batch.changes.is_empty());
    }

    /// A writer that never goes quiet (sub-debounce cadence, like a
    /// campaign fleet writing findings continuously) must not starve the
    /// state refresh: staleness stays bounded by the debounce window
    /// instead of "until the writer exits".
    #[test]
    fn sustained_writer_cannot_starve_the_state_refresh() {
        let (_input, wake) = TerminalLoopInbox::channel_for_test();
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut watcher = watcher_for_test(wake);
        let start = Instant::now();
        let mut applied = false;
        while start.elapsed() < STATE_ARTIFACT_DEBOUNCE * 4 {
            watcher
                .tx
                .try_send(WorkspaceWatcherBatch {
                    changes: Vec::new(),
                    state_artifact_paths: vec![PathBuf::from(".kuzushi/v3/index.sqlite3")],
                })
                .unwrap();
            applied |=
                apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed;
            std::thread::sleep(Duration::from_millis(30));
        }
        assert!(
            applied,
            "a writer that never goes quiet must not defer the refresh forever"
        );
    }

    #[test]
    fn watcher_reconciles_to_the_active_target() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let (_input, wake) = TerminalLoopInbox::channel_for_test();
        let mut watcher = WorkspaceWatcherRuntime::start(Some(first.path()), wake.clone()).unwrap();

        assert!(
            !reconcile_workspace_watcher(&mut watcher, Some(first.path()), wake.clone()).unwrap()
        );
        assert!(
            reconcile_workspace_watcher(&mut watcher, Some(second.path()), wake.clone()).unwrap()
        );
        assert!(watcher
            .as_ref()
            .is_some_and(|runtime| runtime.watches(second.path())));

        assert!(reconcile_workspace_watcher(&mut watcher, None, wake).unwrap());
        assert!(watcher.is_none());
    }

    struct TestWatcherRuntime {
        runtime: WorkspaceWatcherRuntime,
        tx: SyncSender<WorkspaceWatcherBatch>,
    }

    fn watcher_for_test(wake: TerminalLoopWake) -> TestWatcherRuntime {
        let tmp = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::sync_channel(WATCHER_EVENT_CHANNEL_CAPACITY);
        let runtime = WorkspaceWatcherRuntime {
            target: tmp.path().to_path_buf(),
            watcher: WatcherHandle::Ready {
                _keep_alive: LiveWorkspaceWatcher::start(tmp.path(), move |_| wake.notify())
                    .unwrap(),
            },
            rx,
            overflowed: Arc::new(AtomicBool::new(false)),
            deferred_state_artifact_paths: Vec::new(),
            state_artifact_flush_after: None,
            last_state_artifact_flush: None,
        };
        TestWatcherRuntime { runtime, tx }
    }
}

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

pub(crate) struct WorkspaceWatcherRuntime {
    target: PathBuf,
    _watcher: LiveWorkspaceWatcher,
    rx: Receiver<WorkspaceWatcherBatch>,
    overflowed: Arc<AtomicBool>,
    deferred_state_artifact_paths: Vec<PathBuf>,
    state_artifact_flush_after: Option<Instant>,
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
        let watcher = LiveWorkspaceWatcher::start_with_state_events(
            target,
            watcher_sink(tx, overflowed.clone(), wake),
        )?;
        Ok(Some(Self {
            target: target.to_path_buf(),
            _watcher: watcher,
            rx,
            overflowed,
            deferred_state_artifact_paths: Vec::new(),
            state_artifact_flush_after: None,
        }))
    }

    fn watches(&self, target: &Path) -> bool {
        self.target == target
    }

    fn drain_changes(&mut self, release_deferred_state: bool) -> WatcherDrainOutcome {
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
        if new_state_event {
            self.state_artifact_flush_after = Some(Instant::now() + STATE_ARTIFACT_DEBOUNCE);
        }
        if self
            .state_artifact_flush_after
            .is_some_and(|deadline| deadline > Instant::now())
        {
            self.defer_state_artifact_paths(std::mem::take(&mut drained.state_artifact_paths));
        } else {
            self.state_artifact_flush_after = None;
        }
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
            _watcher: LiveWorkspaceWatcher::start(tmp.path(), move |_| wake.notify()).unwrap(),
            rx,
            overflowed: Arc::new(AtomicBool::new(false)),
            deferred_state_artifact_paths: Vec::new(),
            state_artifact_flush_after: None,
        };
        TestWatcherRuntime { runtime, tx }
    }
}

use super::*;
use kuzushi_core::incremental_index::{coalesce_changes, LiveWorkspaceWatcher, WorkspaceChange};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    Arc,
};

const WATCHER_EVENT_CHANNEL_CAPACITY: usize = 4096;
const WATCHER_DRAIN_LIMIT: usize = 256;

pub(crate) struct WorkspaceWatcherRuntime {
    _watcher: LiveWorkspaceWatcher,
    rx: Receiver<Vec<WorkspaceChange>>,
    overflowed: Arc<AtomicBool>,
}

impl WorkspaceWatcherRuntime {
    pub(crate) fn start(target: Option<&Path>, wake: TerminalLoopWake) -> Result<Option<Self>> {
        let Some(target) = target else {
            return Ok(None);
        };
        let (tx, rx) = mpsc::sync_channel(WATCHER_EVENT_CHANNEL_CAPACITY);
        let overflowed = Arc::new(AtomicBool::new(false));
        let watcher =
            LiveWorkspaceWatcher::start(target, watcher_sink(tx, overflowed.clone(), wake))?;
        Ok(Some(Self {
            _watcher: watcher,
            rx,
            overflowed,
        }))
    }

    pub(crate) fn drain_changes(&mut self) -> Vec<WorkspaceChange> {
        let mut changes = overflow_marker(&self.overflowed);
        for _ in 0..WATCHER_DRAIN_LIMIT {
            match self.rx.try_recv() {
                Ok(batch) => changes.extend(batch),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        coalesce_changes(changes)
    }
}

pub(crate) fn apply_watcher_messages(
    app: &mut ShellApp,
    watcher: Option<&mut WorkspaceWatcherRuntime>,
) -> bool {
    let Some(watcher) = watcher else {
        return false;
    };
    let changes = watcher.drain_changes();
    if changes.is_empty() {
        return false;
    }
    update_and_execute_effects(app, Msg::WorkspaceChanged(changes))
}

fn watcher_sink(
    tx: SyncSender<Vec<WorkspaceChange>>,
    overflowed: Arc<AtomicBool>,
    wake: TerminalLoopWake,
) -> impl FnMut(Vec<WorkspaceChange>) + Send + 'static {
    move |changes| {
        if send_watcher_changes(&tx, changes, &overflowed) {
            wake.notify();
        }
    }
}

fn send_watcher_changes(
    tx: &SyncSender<Vec<WorkspaceChange>>,
    changes: Vec<WorkspaceChange>,
    overflowed: &AtomicBool,
) -> bool {
    if changes.is_empty() {
        return false;
    }
    match tx.try_send(changes) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            overflowed.store(true, Ordering::SeqCst);
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

fn overflow_marker(overflowed: &AtomicBool) -> Vec<WorkspaceChange> {
    if overflowed.swap(false, Ordering::SeqCst) {
        vec![WorkspaceChange::GitHeadChanged]
    } else {
        Vec::new()
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
            .try_send(vec![WorkspaceChange::FileChanged("src/routes/a.rs".into())])
            .unwrap();

        assert!(apply_watcher_messages(&mut app, Some(&mut watcher.runtime)));
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

        assert!(apply_watcher_messages(&mut app, Some(&mut watcher.runtime)));

        assert_eq!(
            app.workspace_stale().unwrap().strongest_plan(),
            ReindexPlan::FullSnapshot
        );
    }

    struct TestWatcherRuntime {
        runtime: WorkspaceWatcherRuntime,
        tx: SyncSender<Vec<WorkspaceChange>>,
    }

    fn watcher_for_test(wake: TerminalLoopWake) -> TestWatcherRuntime {
        let tmp = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::sync_channel(WATCHER_EVENT_CHANNEL_CAPACITY);
        let runtime = WorkspaceWatcherRuntime {
            _watcher: LiveWorkspaceWatcher::start(tmp.path(), move |_| wake.notify()).unwrap(),
            rx,
            overflowed: Arc::new(AtomicBool::new(false)),
        };
        TestWatcherRuntime { runtime, tx }
    }
}

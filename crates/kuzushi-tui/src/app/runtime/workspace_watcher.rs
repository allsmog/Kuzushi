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
    applied_state_fingerprints: std::collections::BTreeMap<PathBuf, Option<StateFingerprint>>,
}

/// Identity of a state artifact as last applied. Reads that take file locks
/// open store files with write-capable handles, so closing them emits
/// close-write events without changing the file — each refresh then re-emits
/// events for the very files it read, and the shell invalidates forever.
/// Comparing (len, mtime, platform file identity) drops those phantom reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StateFingerprint {
    len: u64,
    modified: Option<std::time::SystemTime>,
    file_identity: u64,
    is_dir: bool,
}

fn state_fingerprint(target: &Path, relative: &Path) -> Option<StateFingerprint> {
    let metadata = std::fs::symlink_metadata(target.join(relative)).ok()?;
    let file_identity = state_artifact_file_identity(&metadata);
    // A directory's size/mtime churn on every child create/delete — including
    // the sqlite -wal/-shm side files kuzushi's own store reads create and
    // remove — while every real artifact change reports through the child's
    // own path. Directories carry identity only.
    if metadata.is_dir() {
        return Some(StateFingerprint {
            len: 0,
            modified: None,
            file_identity,
            is_dir: true,
        });
    }
    Some(StateFingerprint {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        file_identity,
        is_dir: false,
    })
}

#[cfg(unix)]
use unix_state_artifact_file_identity as state_artifact_file_identity;
#[cfg(not(any(unix, windows)))]
use unsupported_platform_state_artifact_file_identity as state_artifact_file_identity;
#[cfg(windows)]
use windows_state_artifact_file_identity as state_artifact_file_identity;

#[cfg(unix)]
fn unix_state_artifact_file_identity(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.ino()
}

#[cfg(windows)]
fn windows_state_artifact_file_identity(metadata: &std::fs::Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt;
    metadata.creation_time()
}

#[cfg(not(any(unix, windows)))]
fn unsupported_platform_state_artifact_file_identity(_metadata: &std::fs::Metadata) -> u64 {
    0
}

/// Recursive watch registration walks every directory under the target —
/// minutes on monorepo-scale trees — so the handle arrives asynchronously.
/// `Failed` degrades to an unwatched shell instead of aborting it.
enum WatcherHandle {
    Registering(Receiver<Result<LiveWorkspaceWatcher>>),
    Ready { _keep_alive: LiveWorkspaceWatcher },
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatcherRegistrationHealth {
    Ready,
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
            applied_state_fingerprints: std::collections::BTreeMap::new(),
        }))
    }

    fn watches(&self, target: &Path) -> bool {
        self.target == target
    }

    /// Adopt the watcher handle once background registration settles.
    /// Registration health is not a workspace mutation; only channel overflow
    /// may synthesize a full-refresh marker.
    fn adopt_watch_registration(&mut self) -> Option<WatcherRegistrationHealth> {
        let WatcherHandle::Registering(ready) = &self.watcher else {
            return None;
        };
        let (settled, health) = match ready.try_recv() {
            Err(TryRecvError::Empty) => return None,
            Ok(Ok(watcher)) => (
                WatcherHandle::Ready {
                    _keep_alive: watcher,
                },
                WatcherRegistrationHealth::Ready,
            ),
            Ok(Err(_)) | Err(TryRecvError::Disconnected) => {
                (WatcherHandle::Failed, WatcherRegistrationHealth::Failed)
            }
        };
        self.watcher = settled;
        Some(health)
    }

    fn drain_changes(&mut self, release_deferred_state: bool) -> WatcherDrainOutcome {
        let registration_health = self.adopt_watch_registration();
        let mut outcome = self.collect_pending_changes(release_deferred_state);
        outcome.registration_health = registration_health;
        let new_state_event = outcome.new_state_event;
        let drained = &mut outcome.batch;
        drained.changes = coalesce_changes(std::mem::take(&mut drained.changes));
        drained.state_artifact_paths.sort();
        drained.state_artifact_paths.dedup();
        self.debounce_state_artifacts(drained, new_state_event);
        outcome
    }

    fn collect_pending_changes(&mut self, release_deferred_state: bool) -> WatcherDrainOutcome {
        let (mut drained, overflow_state_event) = self.take_overflow_marker();
        self.release_deferred_state_paths(&mut drained, release_deferred_state);
        let (channel_state_event, tail_may_remain) = self.drain_channel_batches(&mut drained);
        WatcherDrainOutcome {
            batch: drained,
            new_state_event: overflow_state_event || channel_state_event,
            tail_may_remain,
            registration_health: None,
        }
    }

    fn take_overflow_marker(&mut self) -> (WorkspaceWatcherBatch, bool) {
        let drained = overflow_marker(&self.overflowed);
        let overflowed = !drained.state_artifact_paths.is_empty();
        if overflowed {
            // Unobserved writes invalidate every applied artifact identity.
            self.applied_state_fingerprints.clear();
        }
        (drained, overflowed)
    }

    fn release_deferred_state_paths(&mut self, drained: &mut WorkspaceWatcherBatch, release: bool) {
        if release {
            drained
                .state_artifact_paths
                .append(&mut self.deferred_state_artifact_paths);
        }
    }

    fn drain_channel_batches(&mut self, drained: &mut WorkspaceWatcherBatch) -> (bool, bool) {
        let mut new_state_event = false;
        for _ in 0..WATCHER_DRAIN_LIMIT {
            match self.rx.try_recv() {
                Ok(batch) => {
                    new_state_event |= !batch.state_artifact_paths.is_empty();
                    drained.merge(batch);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => {
                    return (new_state_event, false);
                }
            }
        }
        (new_state_event, true)
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
        drained
            .state_artifact_paths
            .retain(|path| self.state_artifact_changed(path));
        if !drained.state_artifact_paths.is_empty() {
            self.last_state_artifact_flush = Some(Instant::now());
        }
    }

    /// True when the artifact's on-disk identity differs from the identity
    /// last applied; records the observed identity either way. Lock-only
    /// reopens (close-write with unchanged content) report as unchanged and
    /// must not re-trigger the external-state refresh.
    fn state_artifact_changed(&mut self, relative: &Path) -> bool {
        let current = state_fingerprint(&self.target, relative);
        match self.applied_state_fingerprints.get(relative) {
            Some(previous) if *previous == current => false,
            _ => {
                self.applied_state_fingerprints
                    .insert(relative.to_path_buf(), current);
                true
            }
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
    registration_health: Option<WatcherRegistrationHealth>,
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
    let health_changed = report_watcher_registration_health(app, drained.registration_health);
    let workspace_changed = apply_watcher_batch(app, watcher, drained.batch, work_running);
    WatcherMessageOutcome {
        changed: health_changed || workspace_changed,
        tail_may_remain: drained.tail_may_remain,
    }
}

fn apply_watcher_batch(
    app: &mut ShellApp,
    watcher: &mut WorkspaceWatcherRuntime,
    batch: WorkspaceWatcherBatch,
    work_running: bool,
) -> bool {
    if batch.is_empty() {
        return false;
    }
    // External writers changed the workspace: even when the refresh is
    // deferred/debounced, the liveness badge must stop claiming "idle".
    app.ui_mut().record_external_sync(Instant::now());
    let source_changed = apply_source_changes(app, batch.changes);
    let state_changed =
        apply_state_artifact_changes(app, watcher, batch.state_artifact_paths, work_running);
    source_changed || state_changed
}

fn apply_source_changes(app: &mut ShellApp, changes: Vec<WorkspaceChange>) -> bool {
    if changes.is_empty() {
        return false;
    }
    update_and_execute_effects(app, Msg::WorkspaceChanged(changes))
}

fn apply_state_artifact_changes(
    app: &mut ShellApp,
    watcher: &mut WorkspaceWatcherRuntime,
    paths: Vec<PathBuf>,
    work_running: bool,
) -> bool {
    if paths.is_empty() {
        return false;
    }
    if work_running {
        watcher.defer_state_artifact_paths(paths);
        return false;
    }
    let effects = app.apply_external_workspace_state_change(&paths);
    EffectRuntime::execute(app, effects);
    true
}

fn report_watcher_registration_health(
    app: &mut ShellApp,
    health: Option<WatcherRegistrationHealth>,
) -> bool {
    if health != Some(WatcherRegistrationHealth::Failed) {
        return false;
    }
    app.set_warn_notice(
        "workspace watcher",
        "automatic workspace change detection is unavailable; reopen the target after fixing filesystem watch limits",
    );
    true
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

    #[cfg(any(unix, windows))]
    #[test]
    fn state_artifact_identity_comes_from_platform_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("artifact.json");
        std::fs::write(&path, "{}").unwrap();
        let metadata = std::fs::metadata(path).unwrap();
        #[cfg(unix)]
        let expected = {
            use std::os::unix::fs::MetadataExt;
            metadata.ino()
        };
        #[cfg(windows)]
        let expected = {
            use std::os::windows::fs::MetadataExt;
            metadata.creation_time()
        };

        assert!(expected > 1, "test filesystem returned no stable identity");
        assert_eq!(state_artifact_file_identity(&metadata), expected);
    }

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
            let outcome = apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime));
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

        write_state_artifact(&watcher, ".kuzushi/v3/index.sqlite3", "state-one");
        send_state_event(&watcher);
        assert!(!apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed);
        std::thread::sleep(STATE_ARTIFACT_DEBOUNCE + Duration::from_millis(10));
        assert!(
            apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed,
            "the first quiet window must apply a refresh"
        );

        write_state_artifact(&watcher, ".kuzushi/v3/index.sqlite3", "state-two-longer");
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

    /// Loop breaker for phantom self-invalidation: kuzushi's own store reads
    /// reopen state files through write-capable lock handles, emitting
    /// close-write events with NO content change. Applying a refresh on those
    /// re-reads the stores, which emits the next phantom event — a
    /// self-sustaining cycle that discards every slow hydration result
    /// (rev:unknown forever on large targets). An unchanged artifact identity
    /// must therefore never re-apply the external-state refresh.
    #[test]
    fn unchanged_state_artifact_reopen_does_not_reapply_refresh() {
        let (_input, wake) = TerminalLoopInbox::channel_for_test();
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut watcher = watcher_for_test(wake);
        let send_state_event = |watcher: &TestWatcherRuntime| {
            watcher
                .tx
                .try_send(WorkspaceWatcherBatch {
                    changes: Vec::new(),
                    state_artifact_paths: vec![PathBuf::from(".kuzushi/v3/options.json")],
                })
                .unwrap();
        };
        let expire_cooldown = |watcher: &mut TestWatcherRuntime| {
            watcher.runtime.last_state_artifact_flush =
                Some(Instant::now() - STATE_ARTIFACT_REFRESH_COOLDOWN);
        };

        write_state_artifact(&watcher, ".kuzushi/v3/options.json", r#"{"value":1}"#);
        send_state_event(&watcher);
        assert!(!apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed);
        std::thread::sleep(STATE_ARTIFACT_DEBOUNCE + Duration::from_millis(10));
        assert!(
            apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed,
            "a new artifact identity must apply a refresh"
        );

        // Lock-only reopen: the event arrives with no on-disk change.
        expire_cooldown(&mut watcher);
        send_state_event(&watcher);
        assert!(!apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed);
        std::thread::sleep(STATE_ARTIFACT_DEBOUNCE + Duration::from_millis(10));
        assert!(
            !apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed,
            "an unchanged artifact identity must not re-apply the refresh"
        );

        // A genuine modification still applies.
        write_state_artifact(&watcher, ".kuzushi/v3/options.json", r#"{"value":22}"#);
        expire_cooldown(&mut watcher);
        send_state_event(&watcher);
        assert!(!apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed);
        std::thread::sleep(STATE_ARTIFACT_DEBOUNCE + Duration::from_millis(10));
        assert!(
            apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed,
            "a modified artifact identity must apply a refresh again"
        );
    }

    /// The state dir's mtime churns on every child create/delete — including
    /// sqlite side files kuzushi's own reads produce. Directory-level events
    /// carry no artifact identity of their own (children report through
    /// their own paths), so dir mtime churn must not re-apply the refresh.
    #[test]
    fn state_dir_mtime_churn_does_not_reapply_refresh() {
        let (_input, wake) = TerminalLoopInbox::channel_for_test();
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut watcher = watcher_for_test(wake);
        let send_dir_event = |watcher: &TestWatcherRuntime| {
            watcher
                .tx
                .try_send(WorkspaceWatcherBatch {
                    changes: Vec::new(),
                    state_artifact_paths: vec![PathBuf::from(".kuzushi/v3")],
                })
                .unwrap();
        };

        std::fs::create_dir_all(watcher.target.path().join(".kuzushi/v3")).unwrap();
        send_dir_event(&watcher);
        assert!(!apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed);
        std::thread::sleep(STATE_ARTIFACT_DEBOUNCE + Duration::from_millis(10));
        assert!(
            apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed,
            "the first sighting of the state dir must apply a refresh"
        );

        // Child create/delete bumps the dir mtime without changing identity.
        std::fs::write(
            watcher.target.path().join(".kuzushi/v3/index.sqlite3-wal"),
            "wal",
        )
        .unwrap();
        watcher.runtime.last_state_artifact_flush =
            Some(Instant::now() - STATE_ARTIFACT_REFRESH_COOLDOWN);
        send_dir_event(&watcher);
        assert!(!apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed);
        std::thread::sleep(STATE_ARTIFACT_DEBOUNCE + Duration::from_millis(10));
        assert!(
            !apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed,
            "dir mtime churn from child side files must not re-apply the refresh"
        );
    }

    /// Overflow means writes went unobserved; its `.kuzushi/v3` refresh
    /// sentinel must bypass the unchanged-identity gate even when the dir
    /// was already applied.
    #[test]
    fn overflow_refresh_sentinel_bypasses_the_unchanged_gate() {
        let (_input, wake) = TerminalLoopInbox::channel_for_test();
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut watcher = watcher_for_test(wake);
        std::fs::create_dir_all(watcher.target.path().join(".kuzushi/v3")).unwrap();
        let applied = state_fingerprint(watcher.target.path(), Path::new(".kuzushi/v3"));
        assert!(applied.is_some());
        watcher
            .runtime
            .applied_state_fingerprints
            .insert(PathBuf::from(".kuzushi/v3"), applied);
        watcher.runtime.overflowed.store(true, Ordering::SeqCst);

        // The overflow marker's GitHeadChanged applies immediately; the state
        // sentinel defers into the debounce window.
        apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime));
        std::thread::sleep(STATE_ARTIFACT_DEBOUNCE + Duration::from_millis(10));
        assert!(
            apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime)).changed,
            "the overflow sentinel must apply a refresh despite an applied identity"
        );
    }

    /// `start` must return without waiting for the recursive watch walk —
    /// a blocking walk deafens the shell to input for minutes on large
    /// targets. Clean registration is health-only and must not fabricate a
    /// source or `.kuzushi` change.
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
            let _ = runtime.adopt_watch_registration();
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(matches!(runtime.watcher, WatcherHandle::Ready { .. }));
        let refresh = runtime.drain_changes(true);
        assert!(refresh.batch.changes.is_empty());
        assert!(refresh.batch.state_artifact_paths.is_empty());
        assert!(runtime.drain_changes(true).batch.changes.is_empty());
    }

    /// A registration thread that dies (unreadable root, inotify limits)
    /// reports degraded health without claiming the source snapshot changed.
    #[test]
    fn failed_registration_degrades_instead_of_aborting() {
        let (_input, wake) = TerminalLoopInbox::channel_for_test();
        let mut watcher = watcher_for_test(wake);
        let (ready_tx, ready_rx) = mpsc::channel::<Result<LiveWorkspaceWatcher>>();
        watcher.runtime.watcher = WatcherHandle::Registering(ready_rx);
        drop(ready_tx);

        let mut app = ShellApp::new(V2Config::default(), None);
        let outcome = apply_watcher_messages_with_outcome(&mut app, Some(&mut watcher.runtime));

        assert!(matches!(watcher.runtime.watcher, WatcherHandle::Failed));
        assert!(outcome.changed);
        assert!(app.workspace_stale().is_none());
        assert!(app
            .advisory()
            .notice
            .as_ref()
            .is_some_and(|notice| notice.source == "workspace watcher"));
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
        let mut version = 0usize;
        while start.elapsed() < STATE_ARTIFACT_DEBOUNCE * 4 {
            version += 1;
            write_state_artifact(
                &watcher,
                ".kuzushi/v3/index.sqlite3",
                &format!("v{version}-{}", "x".repeat(version)),
            );
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
        target: tempfile::TempDir,
    }

    fn write_state_artifact(watcher: &TestWatcherRuntime, relative: &str, content: &str) {
        let path = watcher.target.path().join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
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
            applied_state_fingerprints: std::collections::BTreeMap::new(),
        };
        TestWatcherRuntime {
            runtime,
            tx,
            target: tmp,
        }
    }
}

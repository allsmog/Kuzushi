use super::requests::active_view_hydration_keys;
use super::runtime::MAX_VIEW_HYDRATION_WORKERS;
use super::*;
use crate::renderer::render_app;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
struct CountingReader {
    reads: AtomicUsize,
}

impl ViewArtifactReader for CountingReader {
    fn read(&self, _target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        self.reads.fetch_add(1, Ordering::SeqCst);
        missing_value(key)
    }
}

fn missing_value(key: &ViewHydrationKey) -> ViewHydrationValue {
    match key {
        ViewHydrationKey::LatestRunPointer => {
            ViewHydrationValue::LatestRunPointer(LatestRunPointerState::Missing)
        }
        ViewHydrationKey::RunSummaryEntries => ViewHydrationValue::RunSummaryEntries(Vec::new()),
        ViewHydrationKey::RunArtifactText { run_id, leaf } => {
            ViewHydrationValue::RunArtifactText(kuzushi_core::RunArtifactRead::Missing {
                path: PathBuf::from(run_id).join(leaf),
            })
        }
        ViewHydrationKey::RunTrace { .. } => ViewHydrationValue::RunTrace(None),
        ViewHydrationKey::SourceFile { .. } => {
            ViewHydrationValue::SourceFile(Err("missing fixture source".to_string()))
        }
        ViewHydrationKey::GitMetadata => ViewHydrationValue::GitMetadata(None),
        ViewHydrationKey::ProjectScopeTree => {
            ViewHydrationValue::ProjectScopeTree(ProjectScopeTreeState::RootOnly)
        }
        ViewHydrationKey::ProjectModelDocument { .. } => {
            ViewHydrationValue::ProjectModelDocument(None)
        }
        ViewHydrationKey::StrategyQueue => {
            ViewHydrationValue::StrategyQueue(StrategyQueueState::Ready(Vec::new()))
        }
        ViewHydrationKey::PromptMutations => {
            ViewHydrationValue::PromptMutations(PromptMutationsState::Ready(Vec::new()))
        }
        ViewHydrationKey::HarnessFile => ViewHydrationValue::HarnessFile(None),
        ViewHydrationKey::JsonFile { .. } => ViewHydrationValue::JsonFile(JsonFileState::Missing),
        ViewHydrationKey::PathState { .. } => ViewHydrationValue::PathState(PathState::Missing),
        ViewHydrationKey::DirectoryListing { .. } => {
            ViewHydrationValue::DirectoryListing(DirectoryListingState::Missing)
        }
        ViewHydrationKey::PromptOverrideHash { .. } => {
            ViewHydrationValue::PromptOverrideHash(Ok(None))
        }
        ViewHydrationKey::HealthChecks { .. } => {
            ViewHydrationValue::HealthChecks(ViewHealthChecks {
                semgrep_error: None,
                codeql_error: None,
                joern_path: None,
                credential_set: false,
                configured_joern_cpg: None,
            })
        }
        ViewHydrationKey::MapArtifacts => ViewHydrationValue::MapArtifacts(false),
        ViewHydrationKey::TargetBase => ViewHydrationValue::TargetBase("target".to_string()),
    }
}

#[test]
fn cold_artifact_backed_views_do_not_touch_the_reader_during_render() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let reader = Arc::new(CountingReader::default());
    app.set_view_artifact_reader_for_test(reader.clone());
    app.set_focused_module(Some("sast".to_string()));
    let mut terminal = Terminal::new(TestBackend::new(100, 36)).unwrap();

    for view in [
        ShellView::Home,
        ShellView::Recommend,
        ShellView::Module,
        ShellView::Workbench,
        ShellView::Tune,
        ShellView::Threat,
        ShellView::PromptsEditor,
        ShellView::Runs,
        ShellView::Jobs,
        ShellView::RunDiff,
        ShellView::Replay,
        ShellView::Trace,
        ShellView::Health,
        ShellView::ProjectModel,
        ShellView::StrategyQueue,
        ShellView::FailureHandoff,
        ShellView::AgentChat,
        ShellView::Activity,
        ShellView::PlanningPicker,
        ShellView::Scene,
    ] {
        render_cold_view(&mut terminal, &mut app, view);
    }

    assert_eq!(reader.reads.load(Ordering::SeqCst), 0);
}

fn render_cold_view(terminal: &mut Terminal<TestBackend>, app: &mut ShellApp, view: ShellView) {
    match view {
        ShellView::RunDiff => app.open_run_diff_for_test("run-left", "run-right"),
        ShellView::Replay => app.open_replay_for_test("run-replay"),
        ShellView::Trace => app.open_trace_for_test("run-trace"),
        _ => app.set_shell_view(view),
    }
    terminal.draw(|frame| render_app(frame, app)).unwrap();
}

#[test]
fn scheduling_the_same_key_twice_deduplicates_the_read() {
    let temp = tempfile::tempdir().unwrap();
    let reader = Arc::new(CountingReader::default());
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(reader.clone());
    let key = ViewHydrationKey::LatestRunPointer;

    assert_eq!(
        runtime
            .schedule(temp.path().to_path_buf(), vec![key.clone()], None)
            .len(),
        1
    );
    assert!(runtime
        .schedule(temp.path().to_path_buf(), vec![key], None)
        .is_empty());
    wait_until(|| reader.reads.load(Ordering::SeqCst) == 1);

    assert_eq!(reader.reads.load(Ordering::SeqCst), 1);
}

#[test]
fn workbench_hydrates_the_map_artifact_state() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_shell_view(ShellView::Workbench);

    assert!(active_view_hydration_keys(&app).contains(&ViewHydrationKey::MapArtifacts));
}

#[derive(Debug, Default)]
struct BlockingReader {
    state: Arc<(Mutex<BlockingState>, Condvar)>,
}

#[derive(Debug, Default)]
struct BlockingState {
    started: bool,
    released: bool,
}

impl ViewArtifactReader for BlockingReader {
    fn read(&self, _target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        let (lock, wake) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.started = true;
        wake.notify_all();
        while !state.released {
            state = wake.wait(state).unwrap();
        }
        missing_value(key)
    }
}

#[test]
fn target_generation_discards_a_stale_result() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let reader = Arc::new(BlockingReader::default());
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(reader.clone());
    schedule_latest(&mut runtime, first.path());
    wait_for_reader_start(&reader);

    runtime.schedule(second.path().to_path_buf(), Vec::new(), None);
    release_reader(&reader);
    wait_until(|| runtime.workers_finished());

    assert!(runtime.drain_current().results.is_empty());
}

#[derive(Debug, Default)]
struct PanicReader;

impl ViewArtifactReader for PanicReader {
    fn read(&self, _target: &Path, _key: &ViewHydrationKey) -> ViewHydrationValue {
        panic!("fixture reader panic")
    }
}

#[test]
fn reader_panic_clears_in_flight_key_for_retry() {
    let temp = tempfile::tempdir().unwrap();
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(Arc::new(PanicReader));
    assert_eq!(schedule_latest(&mut runtime, temp.path()).len(), 1);
    wait_until(|| runtime.workers_finished());

    assert_eq!(runtime.drain_current().failures.len(), 1);
    assert_eq!(schedule_latest(&mut runtime, temp.path()).len(), 1);
}

#[test]
fn invalidation_discards_queued_reader_failures() {
    let temp = tempfile::tempdir().unwrap();
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(Arc::new(PanicReader));
    schedule_latest(&mut runtime, temp.path());
    wait_until(|| runtime.workers_finished());

    runtime.invalidate();

    assert!(runtime.drain_current().failures.is_empty());
}

#[test]
fn rapid_target_generations_keep_worker_count_bounded() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let third = tempfile::tempdir().unwrap();
    let reader = Arc::new(BlockingReader::default());
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(reader.clone());

    schedule_latest(&mut runtime, first.path());
    wait_for_reader_start(&reader);
    schedule_latest(&mut runtime, second.path());
    let refused = schedule_latest(&mut runtime, third.path());

    assert!(refused.is_empty());
    assert_eq!(runtime.worker_count(), MAX_VIEW_HYDRATION_WORKERS);
    release_reader(&reader);
}

#[test]
fn same_target_invalidation_discards_pre_invalidation_result() {
    let temp = tempfile::tempdir().unwrap();
    let reader = Arc::new(BlockingReader::default());
    let mut runtime = ViewHydrationRuntime::default();
    runtime.set_reader(reader.clone());

    schedule_latest(&mut runtime, temp.path());
    wait_for_reader_start(&reader);
    runtime.invalidate();
    release_reader(&reader);
    wait_until(|| runtime.workers_finished());

    assert!(runtime.drain_current().results.is_empty());
}

fn schedule_latest(runtime: &mut ViewHydrationRuntime, target: &Path) -> Vec<ViewHydrationKey> {
    runtime.schedule(
        target.to_path_buf(),
        vec![ViewHydrationKey::LatestRunPointer],
        None,
    )
}

fn wait_for_reader_start(reader: &BlockingReader) {
    let (lock, wake) = &*reader.state;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut state = lock.lock().unwrap();
    while !state.started {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "reader did not start");
        let (next, timeout) = wake.wait_timeout(state, remaining).unwrap();
        state = next;
        assert!(
            !timeout.timed_out() || state.started,
            "reader did not start"
        );
    }
}

fn release_reader(reader: &BlockingReader) {
    let (lock, wake) = &*reader.state;
    let mut state = lock.lock().unwrap();
    state.released = true;
    wake.notify_all();
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !condition() && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(condition(), "condition did not become true");
}

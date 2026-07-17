use super::*;
use crate::renderer::render_app;
use ratatui::{backend::TestBackend, Terminal};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
struct CompletionReader {
    reads: AtomicUsize,
}

#[derive(Debug, Default)]
struct LargeCompletionReader {
    reads: AtomicUsize,
}

impl ViewArtifactReader for LargeCompletionReader {
    fn read(&self, _target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        self.reads.fetch_add(1, Ordering::SeqCst);
        match key {
            ViewHydrationKey::FileCompletionValues => ViewHydrationValue::FileCompletionValues(
                FileCompletionIndex::complete(large_file_values()),
            ),
            ViewHydrationKey::FindingCompletionValues => {
                ViewHydrationValue::FindingCompletionValues(Vec::new())
            }
            ViewHydrationKey::RunIdCompletionValues => {
                ViewHydrationValue::RunIdCompletionValues(Vec::new())
            }
            _ => panic!("unexpected completion fixture key: {key:?}"),
        }
    }
}

impl ViewArtifactReader for CompletionReader {
    fn read(&self, _target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        self.reads.fetch_add(1, Ordering::SeqCst);
        match key {
            ViewHydrationKey::FileCompletionValues => {
                ViewHydrationValue::FileCompletionValues(FileCompletionIndex::complete(vec![
                    "src/lib.rs".to_string(),
                ]))
            }
            ViewHydrationKey::FindingCompletionValues => {
                ViewHydrationValue::FindingCompletionValues(vec!["F001".to_string()])
            }
            ViewHydrationKey::RunIdCompletionValues => {
                ViewHydrationValue::RunIdCompletionValues(vec!["run-1".to_string()])
            }
            _ => panic!("unexpected completion fixture key: {key:?}"),
        }
    }
}

#[test]
fn repeated_completion_render_and_tab_do_not_read_again() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let reader = Arc::new(CompletionReader::default());
    app.set_view_artifact_reader_for_test(reader.clone());
    hydrate_completion_keys(&mut app);
    let reads_after_hydration = reader.reads.load(Ordering::SeqCst);
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();

    app.set_input("attach src");
    for _ in 0..3 {
        assert!(
            app.completion_preview().is_some(),
            "candidates: {:?}",
            app.completion_candidates(app.input())
        );
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
    }
    app.apply_completion();

    assert_eq!(reader.reads.load(Ordering::SeqCst), reads_after_hydration);
    assert_eq!(app.input(), "attach src/lib.rs");
}

#[test]
fn five_thousand_file_preview_recomputes_once_until_a_generation_changes() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let reader = Arc::new(LargeCompletionReader::default());
    app.set_view_artifact_reader_for_test(reader.clone());
    hydrate_completion_keys(&mut app);
    app.set_shell_view(ShellView::Workbench);
    app.set_input("attach src/file-4999");
    let reads = reader.reads.load(Ordering::SeqCst);
    let provider_reads = app.completion_source_reads_for_test();
    let recomputations = app.completion_preview_recomputations_for_test();
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();

    for _ in 0..5 {
        terminal.draw(|frame| render_app(frame, &app)).unwrap();
    }

    assert_eq!(reader.reads.load(Ordering::SeqCst), reads);
    assert_eq!(app.completion_source_reads_for_test(), provider_reads + 1);
    assert_eq!(
        app.completion_preview_recomputations_for_test(),
        recomputations + 1
    );

    let module_count = app.registry_mut().modules().count();
    assert!(module_count > 0);
    terminal.draw(|frame| render_app(frame, &app)).unwrap();
    assert_eq!(
        app.completion_preview_recomputations_for_test(),
        recomputations + 2
    );
}

#[test]
fn input_and_hydration_generations_invalidate_the_preview_memo() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let reader = Arc::new(LargeCompletionReader::default());
    app.set_view_artifact_reader_for_test(reader);
    hydrate_completion_keys(&mut app);
    app.set_input("attach src/file-4999");
    assert_eq!(app.completion_preview().as_deref(), Some(".rs"));
    let first = app.completion_preview_recomputations_for_test();

    assert_eq!(app.completion_preview().as_deref(), Some(".rs"));
    assert_eq!(app.completion_preview_recomputations_for_test(), first);
    app.insert_char_at_cursor('x');
    assert!(app.completion_preview().is_none());
    assert_eq!(app.completion_preview_recomputations_for_test(), first + 1);

    let target = app.target_owned().unwrap();
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target,
            key: ViewHydrationKey::FileCompletionValues,
            value: ViewHydrationValue::FileCompletionValues(FileCompletionIndex::complete(vec![
                "src/file-4999x.rs".to_string(),
            ])),
        });
    assert_eq!(app.completion_preview().as_deref(), Some(".rs"));
    assert_eq!(app.completion_preview_recomputations_for_test(), first + 2);
}

#[test]
fn progress_mutations_preserve_preview_until_a_live_run_id_changes() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_view_artifact_reader_for_test(Arc::new(CompletionReader::default()));
    hydrate_completion_keys(&mut app);
    app.set_scan_panel(Some(ScanPanelState {
        run_id: Some("scan-1".to_string()),
        target: temp.path().to_path_buf(),
        stage: "queued".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }));
    app.set_activity(Some(ActivitySession::new("activity-1")));
    app.set_input("attach src");
    assert_eq!(app.completion_preview().as_deref(), Some("/lib.rs"));
    let recomputations = app.completion_preview_recomputations_for_test();

    app.scan_mut().expect("scan").stage = "triage".to_string();
    app.activity_mut().expect("activity").mark_terminal();
    assert_eq!(app.completion_preview().as_deref(), Some("/lib.rs"));
    assert_eq!(
        app.completion_preview_recomputations_for_test(),
        recomputations
    );

    app.set_activity_run_id("activity-2".to_string());
    assert_eq!(app.completion_preview().as_deref(), Some("/lib.rs"));
    assert_eq!(
        app.completion_preview_recomputations_for_test(),
        recomputations + 1
    );
}

#[test]
fn identical_completion_hydration_does_not_invalidate_the_preview() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_view_artifact_reader_for_test(Arc::new(CompletionReader::default()));
    hydrate_completion_keys(&mut app);
    app.set_input("attach src");
    assert_eq!(app.completion_preview().as_deref(), Some("/lib.rs"));
    let recomputations = app.completion_preview_recomputations_for_test();
    let target = app.target_owned().expect("target");

    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target,
            key: ViewHydrationKey::FileCompletionValues,
            value: ViewHydrationValue::FileCompletionValues(FileCompletionIndex::complete(vec![
                "src/lib.rs".to_string(),
            ])),
        });

    assert_eq!(app.completion_preview().as_deref(), Some("/lib.rs"));
    assert_eq!(
        app.completion_preview_recomputations_for_test(),
        recomputations
    );
}

#[test]
fn completion_cache_does_not_cross_target_generations() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let mut cache = WorkbenchCache::default();
    cache.apply_view_hydration(ViewHydrationResult {
        target: first.path().to_path_buf(),
        key: ViewHydrationKey::FileCompletionValues,
        value: ViewHydrationValue::FileCompletionValues(FileCompletionIndex::complete(vec![
            "first.rs".to_string(),
        ])),
    });

    assert_eq!(
        cache.cached_file_completion_values(Some(first.path())),
        vec!["first.rs".to_string()]
    );
    assert!(cache
        .cached_file_completion_values(Some(second.path()))
        .is_empty());
}

#[test]
fn target_round_trip_invalidates_an_old_preview_even_when_the_path_matches_again() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(first.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_view_artifact_reader_for_test(Arc::new(CompletionReader::default()));
    hydrate_completion_keys(&mut app);
    let first_target = app.target_owned().unwrap();
    let second_target = WorkspaceTarget::new(second.path())
        .unwrap()
        .root()
        .to_path_buf();
    app.set_input("attach src");
    assert_eq!(app.completion_preview().as_deref(), Some("/lib.rs"));
    let recomputations = app.completion_preview_recomputations_for_test();

    app.set_target(Some(second_target));
    app.set_target(Some(first_target));

    assert_eq!(app.completion_preview().as_deref(), Some("/lib.rs"));
    assert_eq!(
        app.completion_preview_recomputations_for_test(),
        recomputations + 1
    );
}

#[test]
fn workspace_refresh_updates_cache_without_changing_active_tab_cycle() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("a.rs"), "a").unwrap();
    std::fs::write(temp.path().join("b.rs"), "b").unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.hydrate_active_view_blocking();
    app.set_input("attach ");
    app.apply_completion();
    assert_eq!(app.input(), "attach a.rs");

    std::fs::write(temp.path().join("aa.rs"), "aa").unwrap();
    app.apply_workspace_changes(&[]);
    app.hydrate_active_view_blocking();
    assert!(app
        .completion_candidates("attach aa")
        .contains(&"attach aa.rs".to_string()));

    app.apply_completion();
    assert_eq!(app.input(), "attach b.rs");
}

fn hydrate_completion_keys(app: &mut ShellApp) {
    let target = app.target_owned().expect("completion fixture target");
    app.hydrate_view_keys_blocking(
        &target,
        vec![
            ViewHydrationKey::FileCompletionValues,
            ViewHydrationKey::FindingCompletionValues,
            ViewHydrationKey::RunIdCompletionValues,
        ],
    );
}

fn large_file_values() -> Vec<String> {
    (0..5_000)
        .map(|index| format!("src/file-{index:04}.rs"))
        .collect()
}

use super::*;
use kuzushi_core::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
use kuzushi_core::{RunSummary, RunTargetGitMetadata};
use std::fs;
use std::time::Instant;

fn seed_source(root: &Path, count: usize) {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("README.md"), "Synthetic findings and commit metadata for bounded Review measurements. Source is never executed.\n").unwrap();
    let mut source = "// Labeled benign measurement source, never executed.\n".to_owned();
    for index in 0..count {
        source.push_str(&format!(
            "pub fn item_{index:04}() -> usize {{ {index} }}\n"
        ));
    }
    fs::write(root.join("src/lib.rs"), source).unwrap();
}

fn fixture_findings(count: usize) -> Vec<Finding> {
    (0..count)
        .map(|index| {
            Finding::new_tool(
                "fixture",
                &format!("fixture.large.{index:04}"),
                "src/lib.rs",
                index as u32 + 2,
                None,
                Severity::High,
                &format!("Synthetic Review candidate {index:04}"),
            )
        })
        .collect()
}

fn write_revision(root: &Path, run: &str) {
    let mut summary = RunSummary::running(run, "fixture:scan", None, root.display().to_string());
    summary.target_git = Some(RunTargetGitMetadata {
        sha: "a".repeat(40),
        branch: Some("main".into()),
        dirty: false,
    });
    kuzushi_core::write_run_summary(root, &summary.complete()).unwrap();
}

fn seed_ledger(workspace: &WorkspaceTarget, count: usize) {
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let findings = fixture_findings(count);
    store
        .record_run_started("large-a", workspace.root(), "completed")
        .unwrap();
    let ids = store.insert_findings("large-a", &findings).unwrap();
    let decision = ReviewDecision {
        verdict: ReviewDecisionVerdict::Confirmed,
        author: TriageAuthor::Human,
        confidence: 1.0,
        rationale: "Synthetic operator verdict on source A".into(),
        dismiss_reason: None,
        actor: Some("fixture-operator".into()),
    };
    for id in ids {
        store.append_user_review_decision(id, &decision).unwrap();
    }
    store
        .record_run_started("large-b", workspace.root(), "completed")
        .unwrap();
    store.insert_findings("large-b", &findings).unwrap();
    for run in ["large-a", "large-b"] {
        write_revision(workspace.root(), run);
    }
}

fn measure_ledger(workspace: &WorkspaceTarget) -> serde_json::Value {
    let started = Instant::now();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let open_ms = started.elapsed().as_secs_f64() * 1000.0;
    let started = Instant::now();
    let findings = store.list_all_findings().unwrap();
    let list_ms = started.elapsed().as_secs_f64() * 1000.0;
    let started = Instant::now();
    let completion =
        kuzushi_core::workspace::review_completion_for_findings(workspace, &store, &findings)
            .unwrap();
    let completion_ms = started.elapsed().as_secs_f64() * 1000.0;
    let operator = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(workspace));
    let started = Instant::now();
    app.refresh_findings_with_operator_state(false, operator.path());
    let refresh_ms = started.elapsed().as_secs_f64() * 1000.0;
    let started = Instant::now();
    let queue = crate::ui_view_models::review_queue_model(
        &app,
        crate::ui_view_models::ReviewQueueMode::All,
    );
    let queue_ms = started.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(completion.reviewed, findings.len());
    assert_eq!(app.findings_total_count(), findings.len());
    assert_eq!(queue.total_count, app.findings().len());
    serde_json::json!({"findingCount":findings.len(),"loadedFindingCount":app.findings().len(),"partialFindings":app.domain().findings_are_partial(),"reviewed":completion.reviewed,"openMs":open_ms,"listMs":list_ms,"completionMs":completion_ms,"refreshMs":refresh_ms,"queueMs":queue_ms})
}

#[test]
fn measure_existing_large_review_fixture() {
    let Some(path) = std::env::var_os("KUZUSHI_LARGE_REVIEW_MEASURE_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(path);
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let mut receipt = measure_ledger(&workspace);
    receipt["findingsAreSynthetic"] = true.into();
    receipt["commitMetadataIsSynthetic"] = true.into();
    receipt["providerRequests"] = 0.into();
    receipt["sourceExecuted"] = false.into();
    fs::write(
        root.join("large-review-receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    println!("{receipt}");
}

#[test]
fn write_bounded_large_review_fixture_decisions() {
    let Some(path) = std::env::var_os("KUZUSHI_LARGE_REVIEW_WRITER_ROOT") else {
        return;
    };
    let receipt_path = std::env::var_os("KUZUSHI_LARGE_REVIEW_WRITER_RECEIPT").unwrap();
    let root = std::path::PathBuf::from(path);
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = store.list_all_findings().unwrap().pop().unwrap();
    let started = Instant::now();
    let mut durations = Vec::new();
    for index in 0..6 {
        let decision = ReviewDecision {
            verdict: if index % 2 == 0 {
                ReviewDecisionVerdict::Deferred
            } else {
                ReviewDecisionVerdict::Confirmed
            },
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: format!("Synthetic external decision {index}"),
            dismiss_reason: None,
            actor: Some("fixture-external-writer".into()),
        };
        let write_started = Instant::now();
        store
            .append_user_review_decision(finding.id.unwrap(), &decision)
            .unwrap();
        durations.push(write_started.elapsed().as_secs_f64() * 1000.0);
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let receipt = serde_json::json!({"decisionsWritten":6,"elapsedMs":started.elapsed().as_secs_f64()*1000.0,"writeDurationsMs":durations,"providerRequests":0,"sourceExecuted":false});
    fs::write(receipt_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    println!("{receipt}");
}

#[test]
fn prepare_large_review_measurement_fixture() {
    let Some(path) = std::env::var_os("KUZUSHI_LARGE_REVIEW_FIXTURE_OUT") else {
        return;
    };
    let count = std::env::var("KUZUSHI_LARGE_REVIEW_FIXTURE_COUNT")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert!((1..=1000).contains(&count));
    let root = std::path::PathBuf::from(path);
    fs::create_dir_all(&root).unwrap();
    seed_source(&root, count);
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let started = Instant::now();
    seed_ledger(&workspace, count);
    let preparation_ms = started.elapsed().as_secs_f64() * 1000.0;
    let mut receipt = measure_ledger(&workspace);
    receipt["preparationMs"] = preparation_ms.into();
    receipt["findingsAreSynthetic"] = true.into();
    receipt["commitMetadataIsSynthetic"] = true.into();
    receipt["providerRequests"] = 0.into();
    receipt["sourceExecuted"] = false.into();
    fs::write(
        root.join("large-review-receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    println!("{receipt}");
}

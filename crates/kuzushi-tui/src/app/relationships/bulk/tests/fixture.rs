use super::*;
use std::path::Path;

fn prepare(
    target: &Path,
) -> (
    kuzushi_core::WorkspaceTarget,
    FindingStore,
    Vec<FindingRelationship>,
) {
    std::fs::create_dir_all(target).unwrap();
    std::fs::write(
        target.join("hello.txt"),
        "Owned greeting. Never executed.\n",
    )
    .unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(target).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("owned-observations", target, "completed")
        .unwrap();
    let ids = (0..4)
        .map(|index| {
            store
                .insert_finding(
                    "owned-observations",
                    &Finding::new_tool(
                        "owned-fixture",
                        &format!("greeting-{index}"),
                        "hello.txt",
                        1,
                        None,
                        if index == 0 {
                            Severity::Medium
                        } else {
                            Severity::Info
                        },
                        "Labeled greeting observation. No defect is claimed.",
                    ),
                )
                .unwrap()
        })
        .collect::<Vec<_>>();
    let records = ids[1..]
        .iter()
        .map(|id| {
            store
                .propose_finding_relationship(
                    ids[0],
                    *id,
                    FindingRelationshipKind::Duplicate,
                    "Labeled same greeting for operator grouping",
                    None,
                )
                .unwrap()
        })
        .collect::<Vec<_>>();
    (workspace, store, records)
}

pub(super) fn app() -> (tempfile::TempDir, ShellApp, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    let (workspace, store, _records) = prepare(root.path());
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    app.refresh_findings(false);
    app.set_shell_view(ShellView::Relationships);
    app.set_input_mode(InputMode::Navigate);
    app.workbench_cache()
        .borrow_mut()
        .apply_view_hydration(ViewHydrationResult {
            target: workspace.root().into(),
            key: ViewHydrationKey::FindingRelationships {
                finding_id: None,
                offset: 0,
            },
            value: ViewHydrationValue::FindingRelationships(Ok(store
                .finding_relationships(None, 50, 0)
                .unwrap())),
        });
    (root, app, store)
}

#[test]
fn prepare_native_bulk_relationship_fixture() {
    let Some(root) = std::env::var_os("KUZUSHI_BULK_RELATIONSHIP_FIXTURE_OUT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let (workspace, _store, records) = prepare(&root);
    let receipt = serde_json::json!({"relationships":records,"findingsAreSynthetic":true,"providerRequests":0,"sourceExecuted":false});
    std::fs::write(
        workspace.root().join(".kuzushi/bulk-fixture.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    let ledger = workspace
        .root()
        .join(".kuzushi/v3/workflow/phase-attempts.jsonl");
    std::fs::create_dir_all(ledger.parent().unwrap()).unwrap();
    let lines=["map","scan"].into_iter().map(|phase|serde_json::json!({"event":"phase_checkpoint_skipped","phase":phase,"targetSnapshot":{"target":root,"dirty":false},"recordedAtUnix":1}).to_string()).collect::<Vec<_>>().join("\n");
    std::fs::write(ledger, lines + "\n").unwrap();
}

use super::*;
use crate::findings::{GroundingStatus, Severity};

const ORIGINAL: &str = "// owned original source\n// retained full file\n";

struct Fixture {
    _temp: tempfile::TempDir,
    workspace: WorkspaceTarget,
    store: FindingStore,
    snapshot: crate::incremental_index::IndexedWorkspaceSnapshot,
    finding: Finding,
    supplied: BTreeMap<String, String>,
}

impl Fixture {
    fn new(path: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        workspace.ensure_state_dir().unwrap();
        std::fs::write(workspace.root().join(path), ORIGINAL).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let snapshot =
            crate::incremental_index::register_workspace_tree_identity(&workspace).unwrap();
        store
            .insert_scan_run("owned", workspace.root(), "running")
            .unwrap();
        let mut finding = Finding::new_tool(
            "CWE-20",
            "owned-metadata",
            path,
            1,
            None,
            Severity::Info,
            "Owned observation",
        );
        finding.evidence = vec![FindingEvidence {
            kind: FindingEvidence::UNSCORED_SOURCE_CITATION.into(),
            file_path: path.into(),
            line: 1,
            snippet: "// owned original source".into(),
            ..Default::default()
        }];
        let supplied = BTreeMap::from([(path.into(), "// owned".into())]);
        Self {
            _temp: temp,
            workspace,
            store,
            snapshot,
            finding,
            supplied,
        }
    }

    fn capture(&self, maximum: usize) -> Result<CapturedFindingSources> {
        self.store.capture_finding_sources(
            &self.snapshot.snapshot_hash,
            &self.snapshot.tree_hash,
            &self.supplied,
            std::slice::from_ref(&self.finding),
            maximum,
            &|| false,
        )
    }

    fn observations(&self) -> i64 {
        self.store
            .conn
            .query_row("select count(*) from finding_observations", [], |row| {
                row.get(0)
            })
            .unwrap()
    }
}

#[test]
fn frozen_observation_retains_original_snapshot_bytes_and_evidence_after_live_edit_and_restart() {
    let f = Fixture::new("owned.c");
    let captured = f.capture(1024).unwrap();
    std::fs::write(
        f.workspace.root().join("owned.c"),
        "// changed after capture\n",
    )
    .unwrap();
    f.store
        .insert_finding_with_sources("owned", &f.finding, &captured)
        .unwrap();
    let (snapshot, blob): (String, String) = f
        .store
        .conn
        .query_row(
            "select snapshot_hash,blob_hash from finding_observations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(snapshot, f.snapshot.snapshot_hash);
    assert_eq!(
        f.store.read_observation_blob(&blob).unwrap().unwrap(),
        ORIGINAL.as_bytes()
    );
    let finding = f
        .store
        .get_finding_by_fingerprint(&f.finding.fingerprint)
        .unwrap()
        .unwrap();
    assert!(matches!(
        finding.grounding,
        Some(GroundingStatus::Grounded { .. })
    ));
    assert_eq!(
        finding.evidence[0].kind,
        FindingEvidence::UNSCORED_SOURCE_CITATION
    );
    assert_eq!(finding.evidence[0].confidence, 0);
    let reopened = FindingStore::open(f.workspace.findings_db_path()).unwrap();
    assert_eq!(
        reopened.read_observation_blob(&blob).unwrap().unwrap(),
        ORIGINAL.as_bytes()
    );
}

#[test]
fn capture_refuses_changed_files_or_unrelated_supplied_prefix_before_any_observation() {
    let mut f = Fixture::new("owned.c");
    f.supplied
        .insert("owned.c".into(), "// invented prefix".into());
    assert!(f
        .capture(1024)
        .err()
        .unwrap()
        .to_string()
        .contains("prefix"));
    f.supplied.insert("owned.c".into(), "// owned".into());
    std::fs::write(f.workspace.root().join("owned.c"), "// newer revision\n").unwrap();
    assert!(f
        .capture(1024)
        .err()
        .unwrap()
        .to_string()
        .contains("changed"));
    assert_eq!(f.observations(), 0);
}

#[test]
fn capture_refuses_missing_membership_invalid_identity_and_exhausted_source_bytes() {
    let mut f = Fixture::new("owned.c");
    let error = f.capture(3).err().unwrap().to_string();
    assert!(error.contains("Capture limit 3 B") && error.contains("owned.c"));
    assert!(!error.contains(&f.workspace.root().display().to_string()));
    assert!(f.capture(0).is_err());
    f.finding.file_path = "../outside.c".into();
    assert!(f.capture(1024).is_err());
    f.finding.file_path = "owned.c".into();
    assert!(f
        .store
        .capture_finding_sources(
            "not-a-hash",
            &f.snapshot.tree_hash,
            &f.supplied,
            &[f.finding.clone()],
            1024,
            &|| false,
        )
        .is_err());
    assert_eq!(f.observations(), 0);
}

#[test]
fn insertion_rejects_foreign_target_new_paths_and_source_mismatches_without_events() {
    let mut f = Fixture::new("owned.c");
    let captured = f.capture(1024).unwrap();
    f.finding.evidence[0].snippet = "invented code".into();
    assert!(f
        .store
        .insert_finding_with_sources("owned", &f.finding, &captured)
        .is_err());
    f.finding.evidence[0].snippet = "// owned original source".into();
    f.finding.file_path = "new.c".into();
    assert!(f
        .store
        .insert_finding_with_sources("owned", &f.finding, &captured)
        .is_err());
    f.finding.file_path = "owned.c".into();
    let foreign = Fixture::new("owned.c");
    assert!(foreign
        .store
        .insert_finding_with_sources("owned", &f.finding, &captured)
        .is_err());
    assert_eq!(f.observations(), 0);
    assert_eq!(foreign.observations(), 0);
}

#[test]
fn literal_source_names_and_context_only_citations_keep_their_own_authenticated_bytes() {
    let mut f = Fixture::new(" owned.c ");
    std::fs::write(
        f.workspace.root().join("context.md"),
        "owned context only\n",
    )
    .unwrap();
    f.snapshot = crate::incremental_index::register_workspace_tree_identity(&f.workspace).unwrap();
    f.supplied
        .insert("context.md".into(), "owned context".into());
    f.finding.evidence.push(FindingEvidence {
        kind: FindingEvidence::UNSCORED_SOURCE_CITATION.into(),
        file_path: "context.md".into(),
        line: 1,
        snippet: "owned context only".into(),
        ..Default::default()
    });
    let captured = f.capture(1024).unwrap();
    assert_eq!(captured.captured_counts(), (2, ORIGINAL.len() + 19));
    std::fs::write(f.workspace.root().join(" owned.c "), "changed\n").unwrap();
    std::fs::remove_file(f.workspace.root().join("context.md")).unwrap();
    f.store
        .insert_finding_with_sources("owned", &f.finding, &captured)
        .unwrap();
    let stored = f
        .store
        .get_finding_by_fingerprint(&f.finding.fingerprint)
        .unwrap()
        .unwrap();
    assert_eq!(stored.file_path, " owned.c ");
    assert!(stored.grounding.unwrap().is_grounded());
    assert_eq!(stored.evidence.len(), 2);
}

#[test]
fn canceled_capture_and_invalid_primary_lines_leave_no_observations() {
    let mut f = Fixture::new("owned.c");
    assert!(f
        .store
        .capture_finding_sources(
            &f.snapshot.snapshot_hash,
            &f.snapshot.tree_hash,
            &f.supplied,
            &[f.finding.clone()],
            1024,
            &|| true
        )
        .is_err());
    let source = f.capture(1024).unwrap();
    f.finding.start_line = 999;
    assert!(f
        .store
        .insert_finding_with_sources("owned", &f.finding, &source)
        .is_err());
    assert_eq!(f.observations(), 0);
}

#[test]
fn captured_binding_cannot_be_reused_for_lines_outside_the_supplied_prefix() {
    let mut f = Fixture::new("owned.c");
    let source = f.capture(1024).unwrap();
    f.finding.start_line = 2;
    f.finding.evidence.clear();
    assert!(f
        .store
        .insert_finding_with_sources("owned", &f.finding, &source)
        .is_err());
    f.finding.start_line = 1;
    f.finding.end_line = Some(2);
    assert!(f
        .store
        .insert_finding_with_sources("owned", &f.finding, &source)
        .is_err());
    f.finding.end_line = None;
    f.finding.evidence.push(FindingEvidence {
        kind: FindingEvidence::UNSCORED_SOURCE_CITATION.into(),
        file_path: "owned.c".into(),
        line: 2,
        snippet: "retained full file".into(),
        ..Default::default()
    });
    assert!(f
        .store
        .insert_finding_with_sources("owned", &f.finding, &source)
        .is_err());
    assert_eq!(f.observations(), 0);
}

fn owned_git(root: &Path, arguments: &[&str]) -> String {
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let output = std::process::Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_GLOBAL", null)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            &format!("core.hooksPath={null}"),
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Owned fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

#[test]
fn two_git_revisions_keep_separate_original_shas_and_captured_observation_bytes() {
    let mut f = Fixture::new("owned.c");
    owned_git(f.workspace.root(), &["init", "--quiet"]);
    owned_git(f.workspace.root(), &["add", "owned.c"]);
    owned_git(
        f.workspace.root(),
        &["commit", "--quiet", "-m", "fixture first revision"],
    );
    let first_sha = owned_git(f.workspace.root(), &["rev-parse", "HEAD"]);
    f.snapshot = crate::incremental_index::register_workspace_tree_identity(&f.workspace).unwrap();
    let first_source = f.capture(1024).unwrap();
    f.store
        .insert_finding_with_sources("owned", &f.finding, &first_source)
        .unwrap();
    let newer = ORIGINAL.replace("retained full file", "new contextual source");
    std::fs::write(f.workspace.root().join("owned.c"), &newer).unwrap();
    owned_git(f.workspace.root(), &["add", "owned.c"]);
    owned_git(
        f.workspace.root(),
        &["commit", "--quiet", "-m", "fixture second revision"],
    );
    let second_sha = owned_git(f.workspace.root(), &["rev-parse", "HEAD"]);
    f.snapshot = crate::incremental_index::register_workspace_tree_identity(&f.workspace).unwrap();
    let second_source = f.capture(1024).unwrap();
    f.store
        .insert_scan_run("next", f.workspace.root(), "running")
        .unwrap();
    f.store
        .insert_finding_with_sources("next", &f.finding, &second_source)
        .unwrap();
    let mut statement = f.store.conn.prepare("select s.git_commit,o.blob_hash from finding_observations o join target_snapshots s on s.snapshot_hash=o.snapshot_hash order by o.created_seq").unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!((&rows[0].0, &rows[1].0), (&first_sha, &second_sha));
    assert_ne!(first_sha, second_sha);
    assert_ne!(rows[0].1, rows[1].1);
    assert_eq!(
        f.store.read_observation_blob(&rows[0].1).unwrap().unwrap(),
        ORIGINAL.as_bytes()
    );
    assert_eq!(
        f.store.read_observation_blob(&rows[1].1).unwrap().unwrap(),
        newer.as_bytes()
    );
}

#[test]
fn snapshot_preflight_refuses_oversized_membership_and_wrong_workspace() {
    let f = Fixture::new("owned.c");
    let foreign = Fixture::new("owned.c");
    assert!(f
        .store
        .prepare_finding_source_snapshot(
            foreign.workspace.root(),
            &f.snapshot.snapshot_hash,
            &f.snapshot.tree_hash
        )
        .is_err());
    let store = ContentStore::open(f.workspace.objects_dir()).unwrap();
    let tree = store
        .put_tree(
            (0..100_001)
                .map(|index| crate::content_store::TreeEntry {
                    name: format!("owned-{index}.c"),
                    kind: crate::content_store::TreeEntryKind::Blob,
                    hash: object_hash(ObjectKind::Blob, ORIGINAL.as_bytes()),
                    executable: false,
                })
                .collect(),
        )
        .unwrap();
    let original_hash = Blake3Hash::new(f.snapshot.snapshot_hash.clone()).unwrap();
    let original = store
        .get_bounded(&original_hash, ObjectKind::Snapshot, 64 * 1024)
        .unwrap()
        .unwrap();
    let mut metadata: crate::content_store::TargetSnapshot =
        serde_json::from_slice(&original).unwrap();
    metadata.tree_hash = tree.hash.clone();
    let snapshot = store.put_snapshot(&metadata).unwrap();
    let error = f
        .store
        .prepare_finding_source_snapshot(
            f.workspace.root(),
            snapshot.hash.as_str(),
            tree.hash.as_str(),
        )
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("100000-entry"));
    assert_eq!(f.observations(), 0);
}

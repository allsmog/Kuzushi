mod model_artifact;
mod model_scoring;
mod parity;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::findings::{
    DismissReason, Finding, FindingEvidence, FindingStore, ReviewDecision, ReviewDecisionVerdict,
    Severity, StaticProofState, TriageAuthor, TriageOutcome, TriageVerdict,
};
use crate::review_yield::application::{
    build_review_yield_dataset, export_dataset, extract_review_yield_features, manifest_path_for,
    run_census, DatasetBuild, FeatureCutoff, ReviewFeatureSource,
};
use crate::review_yield::domain::{
    author_bucket, classify_cutoff, identity_match_tier, label_class, normalize_evidence_kind,
    path_bucket, severity_rank, CensusReport, CutoffQuality, LabelClass, FEATURE_FIELD_NAMES,
    IDENTITY_MATCH_TIERS,
};
use crate::review_yield::persistence::{ObservationMeta, ReviewYieldProjectionReader};
use crate::workspace::WorkspaceTarget;

// ---------------------------------------------------------------- fixtures

struct Fixture {
    temp: tempfile::TempDir,
    workspace: WorkspaceTarget,
    store: FindingStore,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repo");
    std::fs::create_dir_all(&root).unwrap();
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "running")
        .unwrap();
    Fixture {
        temp,
        workspace,
        store,
    }
}

impl Fixture {
    fn insert(&self, rule_id: &str, file_path: &str) -> i64 {
        self.insert_in_run("run-1", rule_id, file_path)
    }

    /// Materializes a cited file so the store's evidence verification keeps the
    /// citation instead of downgrading it to unverified reasoning.
    fn write_cited_file(&self, file_path: &str) {
        let path = self.workspace.root().join(file_path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut body = "// filler\n".repeat(11);
        body.push_str("secret snippet text\n");
        std::fs::write(path, body).unwrap();
    }

    fn insert_in_run(&self, run_id: &str, rule_id: &str, file_path: &str) -> i64 {
        self.write_cited_file(file_path);
        self.write_cited_file("src/db.rs");
        let mut finding = Finding::new_semgrep(
            rule_id,
            file_path,
            12,
            Some(14),
            Severity::High,
            "tainted value reaches a sink",
        );
        finding.category = Some("CWE-89".to_string());
        finding.static_proof_state = Some(StaticProofState::SourceSinkLinked);
        finding.exploit_scenario = Some("attacker controls the query".to_string());
        finding.preconditions = vec!["network_reachable".to_string()];
        finding.evidence = vec![evidence("taint-source", 90), evidence("taint-sink", 70)];
        self.store.insert_finding(run_id, &finding).unwrap()
    }

    fn decide(&self, finding_id: i64, verdict: ReviewDecisionVerdict) {
        self.store
            .append_user_review_decision(
                finding_id,
                &ReviewDecision {
                    verdict,
                    author: TriageAuthor::Human,
                    confidence: 1.0,
                    rationale: "reviewed by hand".to_string(),
                    dismiss_reason: None,
                    actor: None,
                },
            )
            .unwrap();
    }

    fn dismiss(&self, finding_id: i64, reason: DismissReason) {
        self.store
            .append_dismissal(finding_id, reason, "policy call", "operator")
            .unwrap();
    }

    fn auto_triage(&self, finding_id: i64) {
        self.store
            .record_auto_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "model said so".to_string(),
                    ..TriageOutcome::default()
                },
            )
            .unwrap();
    }

    fn sql(&self, statement: &str) {
        rusqlite::Connection::open(self.workspace.findings_db_path())
            .unwrap()
            .execute(statement, [])
            .unwrap();
    }

    fn census(&self) -> CensusReport {
        run_census(&self.workspace).unwrap()
    }

    fn build(&self) -> DatasetBuild {
        let reader = ReviewYieldProjectionReader::open(&self.workspace).unwrap();
        build_review_yield_dataset(&reader, &self.workspace).unwrap()
    }

    fn out_path(&self) -> PathBuf {
        self.workspace.root().join("exports/review-yield.jsonl")
    }

    fn scratch(&self) -> &Path {
        self.temp.path()
    }
}

fn evidence(kind: &str, confidence: u8) -> FindingEvidence {
    FindingEvidence {
        kind: kind.to_string(),
        file_path: "src/db.rs".to_string(),
        line: 12,
        snippet: "secret snippet text".to_string(),
        rationale: "secret rationale text".to_string(),
        confidence,
        request_blob: None,
        response_blob: None,
    }
}

/// Pulls every decision's read cutoff back to the first recorded observation
/// so the stale-read branch of the cutoff classification can be exercised. The
/// shell's stale-frame path is the only production producer of that state.
fn backdate_read_cutoff(fixture: &Fixture) {
    fixture.sql(
        "update review_decisions set decision_read_watermark =
           (select min(created_seq) from finding_observations)",
    );
}

// ------------------------------------------------------------ label policy

#[test]
fn label_policy_maps_verdicts_to_binary_classes_and_excludes_policy_outcomes() {
    assert_eq!(
        label_class(ReviewDecisionVerdict::Confirmed),
        LabelClass::Positive
    );
    assert_eq!(
        label_class(ReviewDecisionVerdict::ToFix),
        LabelClass::Positive
    );
    assert_eq!(
        label_class(ReviewDecisionVerdict::RejectedFalsePositive),
        LabelClass::Negative
    );
    assert_eq!(
        label_class(ReviewDecisionVerdict::Confirmed).binary_code(),
        Some(1)
    );
    assert_eq!(
        label_class(ReviewDecisionVerdict::RejectedFalsePositive).binary_code(),
        Some(0)
    );
}

#[test]
fn label_policy_never_reuses_is_terminal() {
    for verdict in [
        ReviewDecisionVerdict::Suppressed,
        ReviewDecisionVerdict::Deferred,
        ReviewDecisionVerdict::AcceptedRisk,
        ReviewDecisionVerdict::NeedsReview,
    ] {
        assert_eq!(
            label_class(verdict),
            LabelClass::Excluded,
            "{verdict:?} is a workflow outcome, not ground truth"
        );
        assert_eq!(label_class(verdict).binary_code(), None);
    }
}

#[test]
fn cutoff_classification_distinguishes_stale_read_barrier_and_missing() {
    assert_eq!(classify_cutoff(None, 10), CutoffQuality::Missing);
    assert_eq!(classify_cutoff(Some(10), 10), CutoffQuality::Missing);
    assert_eq!(classify_cutoff(Some(11), 10), CutoffQuality::Missing);
    assert_eq!(classify_cutoff(Some(9), 10), CutoffQuality::BarrierAtHead);
    assert_eq!(classify_cutoff(Some(8), 10), CutoffQuality::TuiReadWatermark);
    assert!(!CutoffQuality::Missing.is_eligible());
    assert!(CutoffQuality::BarrierAtHead.is_eligible());
}

#[test]
fn author_buckets_never_default_an_unknown_actor_to_auto() {
    assert_eq!(author_bucket("human"), "human");
    assert_eq!(author_bucket("Auto"), "auto");
    assert_eq!(author_bucket("imported"), "imported");
    assert_eq!(author_bucket("finding-store"), "other");
    assert_eq!(author_bucket(""), "other");
}

// ------------------------------------------------------------- normalizers

#[test]
fn identity_match_tier_vocabulary_covers_model_dedupe_and_unknown() {
    for tier in [
        "stable_fp",
        "dedup_collision",
        "dedup_key_cross_run",
        "model_dedupe",
    ] {
        assert_eq!(identity_match_tier(Some(tier)), tier);
    }
    assert_eq!(identity_match_tier(Some("something-else")), "unknown");
    assert_eq!(identity_match_tier(None), "unknown");
    assert_eq!(identity_match_tier(Some("unknown")), "unknown");
    assert!(IDENTITY_MATCH_TIERS.contains(&"model_dedupe"));
}

#[test]
fn path_bucket_classifies_vendor_generated_test_example_docs_config_application() {
    assert_eq!(path_bucket("node_modules/left-pad/index.js"), "vendor");
    assert_eq!(path_bucket("target/debug/build.rs"), "generated");
    assert_eq!(path_bucket("tests/api_spec.rs"), "test");
    assert_eq!(path_bucket("src/api_test.rs"), "test");
    assert_eq!(path_bucket("examples/demo_app.rs"), "example");
    assert_eq!(path_bucket("docs/threats.md"), "docs");
    assert_eq!(path_bucket("Cargo.toml"), "config");
    assert_eq!(path_bucket("src/api/handler.rs"), "application");
    assert_eq!(path_bucket("   "), "unknown");
    // Vendored tests stay vendor: the directory rules are ordered.
    assert_eq!(path_bucket("vendor/lib/tests/thing.rs"), "vendor");
}

#[test]
fn evidence_kind_normalization_is_bounded_and_deterministic() {
    assert_eq!(normalize_evidence_kind("taint-source"), "source");
    assert_eq!(normalize_evidence_kind("SINK"), "sink");
    assert_eq!(normalize_evidence_kind("sanitizer-check"), "sanitizer");
    assert_eq!(normalize_evidence_kind("call-path"), "call_path");
    assert_eq!(normalize_evidence_kind("trace"), "call_path");
    assert_eq!(normalize_evidence_kind("http-request"), "http");
    assert_eq!(normalize_evidence_kind("something-novel"), "other");
    assert_eq!(
        normalize_evidence_kind("source"),
        normalize_evidence_kind(" Source ")
    );
}

#[test]
fn severity_rank_orders_critical_zero_through_unknown_five() {
    assert_eq!(severity_rank(Severity::Critical), 0);
    assert_eq!(severity_rank(Severity::High), 1);
    assert_eq!(severity_rank(Severity::Medium), 2);
    assert_eq!(severity_rank(Severity::Low), 3);
    assert_eq!(severity_rank(Severity::Info), 4);
    assert_eq!(severity_rank(Severity::Unknown), 5);
}

// --------------------------------------------------------------- extractor

fn anchor_json(extra: Value) -> String {
    let mut base = serde_json::json!({
        "severity": "high",
        "tool": "semgrep",
        "rule_id": "sql-injection",
        "category": "CWE-89",
        "file_path": "src/api/handler.rs",
        "identityMatchTier": "dedup_collision",
        "staticProofState": "source_sink_linked",
        "vuln_source": "sarif",
        "exploit_scenario": "attacker controls the query",
        "preconditions": ["network_reachable"],
        "corroboration_count": 2,
        "evidence": [
            {"kind": "taint-source", "confidence": 90, "snippet": "leak", "rationale": "leak"},
            {"kind": "taint-sink", "confidence": 70, "snippet": "leak", "rationale": "leak"}
        ],
        "sources": [{"tool": "semgrep"}]
    });
    merge(&mut base, extra);
    base.to_string()
}

fn merge(base: &mut Value, extra: Value) {
    let (Some(base), Some(extra)) = (base.as_object_mut(), extra.as_object()) else {
        return;
    };
    for (key, value) in extra {
        base.insert(key.clone(), value.clone());
    }
}

fn observation(seq: u64, run_id: &str, tool: &str) -> ObservationMeta {
    ObservationMeta {
        observation_hash: format!("obs-{seq}"),
        snapshot_hash: format!("snap-{seq}"),
        created_seq: seq,
        run_id: run_id.to_string(),
        tool: tool.to_string(),
    }
}

#[test]
fn extractor_ignores_projected_triage_fields_in_snapshot_json() {
    let clean = ReviewFeatureSource {
        anchor_json: anchor_json(Value::Null),
        history: vec![observation(3, "run-1", "semgrep")],
        reopened_count: 0,
    };
    let leaky = ReviewFeatureSource {
        anchor_json: anchor_json(serde_json::json!({
            "triage": {"verdict": "true_positive", "confidence": 0.99, "rationale": "verdict leak"},
            "triaged_by": "human",
            "suppressed": true,
            "snoozed_until": "2099-01-01T00:00:00Z",
            "verification": {"verdict": "confirmed"},
            "message": "message leak",
            "title": "title leak",
            "fingerprint": "fingerprint-leak",
            "identityId": "identity-leak"
        })),
        history: vec![observation(3, "run-1", "semgrep")],
        reopened_count: 0,
    };

    let from_clean = extract_review_yield_features(&clean, FeatureCutoff::EventSeq(9)).unwrap();
    let from_leaky = extract_review_yield_features(&leaky, FeatureCutoff::EventSeq(9)).unwrap();

    assert_eq!(from_clean, from_leaky);
    let serialized = serde_json::to_string(&from_leaky).unwrap();
    for leak in ["leak", "triage", "suppressed", "verification", "fingerprint"] {
        assert!(
            !serialized.contains(leak),
            "{leak} reached the feature vector"
        );
    }
}

#[test]
fn extractor_reports_missing_states_explicitly_instead_of_defaulting() {
    let sparse = ReviewFeatureSource {
        anchor_json: serde_json::json!({
            "severity": "unknown",
            "tool": "mystery-tool",
            "rule_id": "mystery-rule",
            "file_path": ""
        })
        .to_string(),
        history: Vec::new(),
        reopened_count: 0,
    };

    let features = extract_review_yield_features(&sparse, FeatureCutoff::EventSeq(9)).unwrap();

    assert_eq!(features.static_proof_state, "missing");
    assert_eq!(features.vuln_source, "unknown");
    assert_eq!(features.tool_family, "other");
    assert_eq!(features.rule_family, "other");
    assert_eq!(features.path_bucket, "unknown");
    assert_eq!(features.language_family, "unknown");
    assert_eq!(features.identity_match_tier, "unknown");
    assert_eq!(features.grounding_status, "native_or_unspecified");
    assert_eq!(features.max_evidence_confidence, None);
    assert_eq!(features.mean_evidence_confidence_millis, None);
}

#[test]
fn feature_cutoff_event_seq_and_projection_head_share_one_extractor() {
    let source = ReviewFeatureSource {
        anchor_json: anchor_json(Value::Null),
        history: vec![
            observation(2, "run-1", "semgrep"),
            observation(4, "run-2", "codeql"),
        ],
        reopened_count: 1,
    };

    let bounded = extract_review_yield_features(&source, FeatureCutoff::EventSeq(4)).unwrap();
    let head = extract_review_yield_features(&source, FeatureCutoff::ProjectionHead).unwrap();

    assert_eq!(bounded, head);
    assert_eq!(bounded.run_count, 2);
    assert_eq!(bounded.distinct_tool_count, 2);
    assert_eq!(bounded.mean_evidence_confidence_millis, Some(800));
    assert_eq!(bounded.max_evidence_confidence, Some(90));

    // A tighter cutoff must hide the later observation.
    let tight = extract_review_yield_features(&source, FeatureCutoff::EventSeq(3)).unwrap();
    assert_eq!(tight.observation_count, 1);
    assert_eq!(tight.run_count, 1);
}

#[test]
fn feature_object_keys_exactly_match_whitelist() {
    let source = ReviewFeatureSource {
        anchor_json: anchor_json(Value::Null),
        history: Vec::new(),
        reopened_count: 0,
    };
    let features = extract_review_yield_features(&source, FeatureCutoff::ProjectionHead).unwrap();

    let value = serde_json::to_value(&features).unwrap();
    let keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    let expected: BTreeSet<&str> = FEATURE_FIELD_NAMES.iter().copied().collect();
    let actual: BTreeSet<&str> = keys.iter().map(String::as_str).collect();

    assert_eq!(actual, expected);
    assert_eq!(keys.len(), FEATURE_FIELD_NAMES.len());
}

// ----------------------------------------------------------- dataset build

#[test]
fn dataset_rows_prove_anchor_before_cutoff_before_label() {
    let fixture = fixture();
    let finding_id = fixture.insert("sql-injection", "src/api/handler.rs");
    fixture.decide(finding_id, ReviewDecisionVerdict::Confirmed);
    // A later, stronger observation must not become the anchor.
    fixture
        .store
        .record_run_started("run-2", fixture.workspace.root(), "running")
        .unwrap();
    fixture.insert_in_run("run-2", "sql-injection", "src/api/handler.rs");

    let build = fixture.build();

    assert_eq!(build.rows.len(), 1);
    for row in &build.rows {
        assert!(row.anchor_observation.seq <= row.feature_cutoff_seq);
        assert!(row.feature_cutoff_seq < row.label_event.seq);
        assert_eq!(row.features.observation_count, 1);
    }
    // Verified citations survive the store's evidence check, so the shape
    // features are real rather than uniformly downgraded.
    let features = &build.rows[0].features;
    assert!(features.has_source_evidence);
    assert!(features.has_sink_evidence);
    assert!(features.source_sink_linked);
    assert_eq!(features.max_evidence_confidence, Some(90));
    assert_eq!(features.rule_family, "cwe-89");
    assert_eq!(features.language_family, "rust");
}

#[test]
fn dataset_emits_one_row_per_durable_identity() {
    let fixture = fixture();
    let finding_id = fixture.insert("sql-injection", "src/api/handler.rs");
    fixture.decide(finding_id, ReviewDecisionVerdict::Confirmed);
    fixture.decide(finding_id, ReviewDecisionVerdict::ToFix);

    let build = fixture.build();

    assert_eq!(build.rows.len(), 1);
    assert_eq!(build.census.human_decision_events, 2);
    assert_eq!(build.census.adjudicated_identities, 1);
    assert_eq!(build.census.eligible_identities, 1);
    assert_eq!(build.census.positive, 1);
    let groups: BTreeSet<&str> = build
        .rows
        .iter()
        .map(|row| row.identity_group.as_str())
        .collect();
    assert_eq!(groups.len(), build.rows.len());
}

#[test]
fn dataset_excludes_policy_outcomes_and_counts_them() {
    let fixture = fixture();
    let accepted = fixture.insert("weak-crypto", "src/crypto.rs");
    let suppressed = fixture.insert("open-redirect", "src/router.rs");
    fixture.dismiss(accepted, DismissReason::AcceptableRisk);
    fixture.dismiss(suppressed, DismissReason::WontFix);

    let census = fixture.census();

    assert_eq!(census.eligible_identities, 0);
    assert_eq!(census.no_eligible_label, 2);
    assert_eq!(census.policy_transitions, 2);
    assert_eq!(census.by_verdict.get("accepted_risk"), Some(&1));
    assert_eq!(census.by_verdict.get("suppressed"), Some(&1));
    assert_eq!(census.by_dismiss_reason.get("acceptable_risk"), Some(&1));
    assert_eq!(census.by_dismiss_reason.get("wont_fix"), Some(&1));
    assert!(fixture.build().rows.is_empty());
}

#[test]
fn dataset_excludes_auto_and_imported_authors_and_counts_them() {
    let fixture = fixture();
    let auto = fixture.insert("sql-injection", "src/api/handler.rs");
    fixture.auto_triage(auto);
    let imported = fixture.insert("open-redirect", "src/router.rs");
    fixture
        .store
        .append_user_review_decision(
            imported,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Imported,
                confidence: 1.0,
                rationale: "carried over from a previous tool".to_string(),
                dismiss_reason: None,
                actor: None,
            },
        )
        .unwrap();

    let build = fixture.build();

    assert!(build.rows.is_empty());
    assert_eq!(build.census.by_author.get("auto"), Some(&1));
    assert_eq!(build.census.by_author.get("imported"), Some(&1));
    assert_eq!(build.census.human_decision_events, 0);
    assert_eq!(build.census.adjudicated_identities, 0);
}

#[test]
fn dataset_marks_and_excludes_conflicting_reversals() {
    let fixture = fixture();
    let finding_id = fixture.insert("sql-injection", "src/api/handler.rs");
    fixture.decide(finding_id, ReviewDecisionVerdict::Confirmed);
    fixture.decide(finding_id, ReviewDecisionVerdict::RejectedFalsePositive);

    let build = fixture.build();

    assert!(build.rows.is_empty());
    assert_eq!(build.census.conflicted, 1);
    assert_eq!(build.census.eligible_identities, 0);
    assert_eq!(build.census.missing_exact_cutoff, 0);
}

#[test]
fn dataset_excludes_decisions_without_exact_cutoff() {
    let fixture = fixture();
    let finding_id = fixture.insert("sql-injection", "src/api/handler.rs");
    fixture.decide(finding_id, ReviewDecisionVerdict::Confirmed);
    fixture.sql("update review_decisions set decision_read_watermark = null");

    let build = fixture.build();

    assert!(build.rows.is_empty());
    assert_eq!(build.census.missing_exact_cutoff, 1);
    assert_eq!(build.census.cutoff_quality.get("missing"), Some(&1));
}

#[test]
fn dataset_excludes_identities_without_pre_cutoff_observation() {
    let fixture = fixture();
    let finding_id = fixture.insert("sql-injection", "src/api/handler.rs");
    fixture.decide(finding_id, ReviewDecisionVerdict::Confirmed);
    // Push every observation past the decider's read cutoff.
    fixture.sql("update finding_observations set created_seq = 9999");

    let build = fixture.build();

    assert!(build.rows.is_empty());
    assert_eq!(build.census.missing_pre_cutoff_observation, 1);
}

#[test]
fn census_reports_author_dismiss_reason_and_cutoff_splits_on_synthetic_log() {
    let fixture = fixture();
    let confirmed = fixture.insert("sql-injection", "src/api/handler.rs");
    let rejected = fixture.insert("open-redirect", "src/router.rs");
    let accepted = fixture.insert("weak-crypto", "src/crypto.rs");
    fixture.decide(confirmed, ReviewDecisionVerdict::Confirmed);
    fixture.decide(rejected, ReviewDecisionVerdict::RejectedFalsePositive);
    fixture.dismiss(accepted, DismissReason::AcceptableRisk);

    let census = fixture.census();

    assert_eq!(census.decision_events, 3);
    assert_eq!(census.human_decision_events, 3);
    assert_eq!(census.by_author.get("human"), Some(&3));
    assert_eq!(census.by_dismiss_reason.get("acceptable_risk"), Some(&1));
    assert_eq!(census.cutoff_quality.get("barrier_at_head"), Some(&3));
    assert_eq!(census.cutoff_quality.get("tui_read_watermark"), None);
    assert_eq!(census.eligible_identities, 2);
    assert_eq!(census.positive, 1);
    assert_eq!(census.negative, 1);
    assert_eq!(census.no_eligible_label, 1);
    assert_eq!(census.distinct_tool_families, 1);
    assert_eq!(census.distinct_rule_families, 1);
    assert_eq!(census.distinct_repositories, 1);
    assert!(census.projection_applied_seq > 0);
    assert!(census.event_log_head_seq >= census.projection_applied_seq);
    assert!(census.earliest_label_event_seq.is_some());
    assert_eq!(census.task_id, "review_yield_predecision_v1");
}

#[test]
fn census_reports_a_stale_read_cutoff_as_tui_read_watermark() {
    let fixture = fixture();
    let finding_id = fixture.insert("sql-injection", "src/api/handler.rs");
    fixture.insert("open-redirect", "src/router.rs");
    fixture.insert("weak-crypto", "src/crypto.rs");
    fixture.decide(finding_id, ReviewDecisionVerdict::Confirmed);
    backdate_read_cutoff(&fixture);

    let build = fixture.build();

    assert_eq!(
        build.census.cutoff_quality.get("tui_read_watermark"),
        Some(&1)
    );
    assert_eq!(build.rows.len(), 1);
    assert_eq!(
        build.rows[0].quality.cutoff_quality,
        CutoffQuality::TuiReadWatermark
    );
}

// ----------------------------------------------------------------- leakage

#[test]
fn forbidden_fields_never_appear_in_serialized_rows() {
    let fixture = fixture();
    let finding_id = fixture.insert("sql-injection", "src/api/handler.rs");
    fixture.auto_triage(finding_id);
    fixture.decide(finding_id, ReviewDecisionVerdict::Confirmed);

    let out = fixture.out_path();
    let outcome = export_dataset(&fixture.workspace, &out).unwrap();
    assert_eq!(outcome.rows, 1);
    let dataset = std::fs::read_to_string(&out).unwrap();
    let manifest = std::fs::read_to_string(&outcome.manifest_path).unwrap();

    for banned in [
        "\"triage\"",
        "\"triaged_by\"",
        "\"triagedBy\"",
        "\"rationale\"",
        "\"snippet\"",
        "\"file_path\"",
        "\"filePath\"",
        "\"display_path\"",
        "\"message\"",
        "\"title\"",
        "\"dismissed_by\"",
        "\"dismissedBy\"",
        "\"actor\"",
        "\"requestBlob\"",
        "\"responseBlob\"",
        "\"fingerprint\"",
        "\"identityId\"",
    ] {
        assert!(!dataset.contains(banned), "{banned} leaked into the dataset");
    }
    let root = fixture.workspace.root().display().to_string();
    assert!(!dataset.contains(&root));
    assert!(!manifest.contains(&root));
    assert!(!dataset.contains("src/api/handler.rs"));
    let raw_fingerprint =
        crate::incremental_index::workspace_root_fingerprint(fixture.workspace.root());
    assert!(!dataset.contains(&raw_fingerprint));
    assert!(!manifest.contains(&raw_fingerprint));
}

// ----------------------------------------------------------------- export

#[test]
fn export_writes_sorted_jsonl_and_reproducible_digest() {
    let fixture = fixture();
    for (rule, path) in [
        ("sql-injection", "src/api/handler.rs"),
        ("open-redirect", "src/router.rs"),
        ("weak-crypto", "src/crypto.rs"),
    ] {
        let finding_id = fixture.insert(rule, path);
        fixture.decide(finding_id, ReviewDecisionVerdict::Confirmed);
    }

    let first_path = fixture.scratch().join("first.jsonl");
    let second_path = fixture.scratch().join("second.jsonl");
    let first = export_dataset(&fixture.workspace, &first_path).unwrap();
    let second = export_dataset(&fixture.workspace, &second_path).unwrap();

    assert_eq!(first.rows, 3);
    assert_eq!(first.dataset_digest, second.dataset_digest);
    assert!(first.dataset_digest.starts_with("blake3:"));
    let first_bytes = std::fs::read(&first_path).unwrap();
    assert_eq!(first_bytes, std::fs::read(&second_path).unwrap());
    assert_eq!(
        manifest_path_for(&first_path),
        first_path.with_file_name("first.jsonl.manifest.json")
    );

    let ids: Vec<String> = std::fs::read_to_string(&first_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["exampleId"].to_string())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);

    // A changed corpus must change the digest.
    let extra = fixture.insert("path-traversal", "src/files.rs");
    fixture.decide(extra, ReviewDecisionVerdict::RejectedFalsePositive);
    let third = export_dataset(&fixture.workspace, &fixture.scratch().join("third.jsonl")).unwrap();
    assert_ne!(third.dataset_digest, first.dataset_digest);
}

#[test]
fn empty_corpus_exports_valid_empty_dataset_and_census() {
    let fixture = fixture();
    fixture.insert("sql-injection", "src/api/handler.rs");

    let out = fixture.out_path();
    let outcome = export_dataset(&fixture.workspace, &out).unwrap();

    assert_eq!(outcome.rows, 0);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "");
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(&outcome.manifest_path).unwrap()).unwrap();
    assert_eq!(manifest["rowCount"], 0);
    assert_eq!(manifest["census"]["decisionEvents"], 0);
    assert_eq!(manifest["taskId"], "review_yield_predecision_v1");
    assert!(manifest["datasetDigest"]
        .as_str()
        .unwrap()
        .starts_with("blake3:"));
    assert_eq!(fixture.census().eligible_identities, 0);
}

#[test]
fn export_requires_a_recorded_findings_database() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();

    let error = run_census(&workspace).unwrap_err().to_string();

    assert!(error.contains("No recorded findings database"), "{error}");
    assert!(!workspace.findings_db_path().exists());
}

// ----------------------------------------------------------------- schemas

fn schema(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn published_schemas_match_the_rust_feature_and_census_contracts() {
    let example = schema("review-yield.training-example.schema.json");
    let required: Vec<&str> = example["definitions"]["features"]["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(required, FEATURE_FIELD_NAMES);

    let properties = example["definitions"]["features"]["properties"]
        .as_object()
        .unwrap();
    let described: BTreeSet<&str> = properties.keys().map(String::as_str).collect();
    let declared: BTreeSet<&str> = FEATURE_FIELD_NAMES.iter().copied().collect();
    assert_eq!(described, declared);

    // `missing` classifies a decision but is never exported.
    let exported: Vec<&str> = example["definitions"]["quality"]["properties"]["cutoffQuality"]
        ["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(exported, ["tui_read_watermark", "barrier_at_head"]);

    let manifest_schema = schema("review-yield.dataset-manifest.schema.json");
    let census_keys: BTreeSet<&str> = manifest_schema["definitions"]["census"]["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let report = serde_json::to_value(CensusReport::default()).unwrap();
    let report_keys: BTreeSet<&str> = report
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(census_keys, report_keys);
}

// ------------------------------------------------------- scoring end to end

/// The batch scorer reads the store once and then evaluates in memory. This
/// is the only test that puts a real projection behind the evaluator.
#[test]
fn scoring_current_findings_reads_the_store_once_and_scores_every_identity() {
    let fixture = fixture();
    fixture.insert("sql-injection", "src/api/orders.rs");
    fixture.insert("sql-injection", "src/api/users.rs");
    let model = crate::review_yield::persistence::load_model_artifact(
        &parity::parity_fixture_path("model-mixed-depth3.json"),
    )
    .unwrap();
    let reader = ReviewYieldProjectionReader::open(&fixture.workspace).unwrap();

    let scores =
        crate::review_yield::application::score_current_findings(&reader, &model).unwrap();

    assert_eq!(scores.len(), 2);
    for scored in &scores {
        assert!(!scored.identity_id.is_empty());
        assert_eq!(
            scored.signal.eligibility,
            crate::review_yield::domain::ReviewYieldEligibility::Eligible,
            "{}",
            scored.identity_id
        );
        assert_eq!(scored.signal.leaf_id, Some(3));
        assert_eq!(
            scored.signal.rendered_path(),
            vec![
                "0:staticProofState==source_sink_linked",
                "1:evidenceCount<=3.5:left"
            ]
        );
    }
}

#[test]
fn scoring_a_target_with_no_findings_returns_an_empty_table_not_an_error() {
    let fixture = fixture();
    let model = crate::review_yield::persistence::load_model_artifact(
        &parity::parity_fixture_path("model-numeric-small.json"),
    )
    .unwrap();
    let reader = ReviewYieldProjectionReader::open(&fixture.workspace).unwrap();

    let scores =
        crate::review_yield::application::score_current_findings(&reader, &model).unwrap();

    assert!(scores.is_empty());
}

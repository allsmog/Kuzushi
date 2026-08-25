use super::*;
use crate::{ActivitySession, PendingPatch};
use kuzushi_core::workflow_attempts::{
    append_phase_attempt_completed, append_phase_attempt_disposition,
    append_phase_checkpoint_skipped, PhaseAttemptCompleted, PhaseAttemptDerivation,
    PhaseAttemptDisposition, PhaseAttemptDispositionRecorded, PhaseAttemptOutcome,
    PhaseAttemptReceipt, PhaseCheckpointSkipped, PhaseResultAction, PhaseTargetSnapshot,
};
use kuzushi_core::{
    Finding, PatchLifecycleFile, PatchLifecycleRecord, PatchLifecycleState, PersistedProofVerdict,
    PersistedSandboxBackend, PersistedVerification, Severity, V2Config, WorkspaceTarget,
};

#[test]
fn result_actions_name_the_rederived_destination_and_never_advance_fix() {
    assert!(result_action_labels(WorkflowPhase::Map, "completed").contains("Use & Scan"));
    let scan = result_action_labels(WorkflowPhase::Scan, "completed");
    assert!(scan.contains("Use & Review"));
    assert!(!scan.contains("Use & Report"));
    let review = result_action_labels(WorkflowPhase::Review, "completed");
    assert!(review.contains("Commit & Prove"));
    assert!(!result_action_labels(WorkflowPhase::Fix, "completed").contains(" n "));
}

#[test]
fn mutation_survivor_rerun_review_labels_disclose_the_requested_derivation() {
    assert_eq!(phase_rerun_action_label(None), "run again");
    assert_eq!(
        phase_rerun_action_label(Some(PhaseAttemptDerivation::Refine)),
        "refine"
    );
    assert_eq!(
        phase_rerun_action_label(Some(PhaseAttemptDerivation::Regenerate)),
        "regenerate"
    );
}

#[test]
fn result_action_labels_follow_phase_result_key_overrides() {
    let mut config = V2Config::default();
    config.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
        context: "phase_result".to_string(),
        action: "select".to_string(),
        bindings: vec!["ctrl+u".to_string()],
    }];
    let app = ShellApp::new(config, None);

    let label = result_action_label(
        &app,
        PhaseResultAction::Select,
        WorkflowPhase::Map,
        "completed",
        false,
        false,
    );

    assert_eq!(label, "ctrl+u Use map");
}

#[test]
fn failed_native_enrichment_becomes_a_repository_only_map_recovery() {
    let presentation = crate::app::PhaseResultPresentation {
        attempt_id: "map-attempt".to_string(),
        outcome: "failed".to_string(),
        emphasis: crate::PhaseResultEmphasis::DominantDecision,
        compact_summary: crate::PhaseResultCompactSummary {
            phase: WorkflowPhase::Map,
            outcome: PhaseAttemptOutcome::Failed,
            run_count: 1,
            artifact_count: 8,
            changed_findings: 0,
            cost: None,
            revision_recorded: true,
            receipt_recorded: true,
        },
        detail_lines: vec![format!(
            "context:build failed · {}",
            crate::app::CONTEXT_ENRICHMENT_RECOVERY_ERROR
        )],
        detail_rows: vec![crate::app::PhaseResultDetailRow {
            key: None,
            disclosed_keys: std::collections::BTreeSet::new(),
            text: crate::app::CONTEXT_ENRICHMENT_RECOVERY_ERROR.to_string(),
        }],
        semantic_keys: std::collections::BTreeSet::new(),
        actions: vec![PhaseResultAction::Open, PhaseResultAction::RunAgain],
        recommended_next: "retry".to_string(),
    };
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_input_mode(crate::InputMode::Navigate);

    let card = phase_result_card_model(&app, WorkflowPhase::Map, presentation);

    assert_eq!(card.outcome, "recovery ready");
    assert!(card.control_hint.contains("Run repository-only Map"));
    assert!(card.control_hint.contains("Technical details"));
    assert!(card.recommended.contains("change runtime in Config"));
    assert!(!card.detail.contains("does not support LLM enrichment yet"));
}

fn unresolved_map_result_app(config: V2Config) -> (tempfile::TempDir, ShellApp) {
    let target = tempfile::tempdir().expect("temp target");
    seed_indexed_map_run(target.path(), "map-run");
    crate::test_support::append_typed_attempt(
        target.path(),
        WorkflowPhase::Map,
        "map-run",
        PhaseAttemptOutcome::Completed,
    );
    let mut app = ShellApp::new(config, None);
    app.set_target(Some(target.path().to_path_buf()));
    app.refresh_phase_attempt_projection();
    (target, app)
}

fn seed_indexed_map_run(target: &std::path::Path, run_id: &str) {
    crate::test_support::record_indexed_run(
        target,
        run_id,
        "context:build",
        serde_json::json!({
            "ok": true,
            "data": {"snapshot": {"filesIndexed": 1}}
        }),
    );
}

fn map_result_control_hint(app: &ShellApp) -> String {
    phase_cockpit_model_for_phase(app, WorkflowPhase::Map)
        .header
        .result_card
        .expect("unresolved map result")
        .control_hint
}

#[test]
fn phase_result_card_discloses_controls_for_the_active_input_mode() {
    let (_target, mut app) = unresolved_map_result_app(V2Config::default());

    assert_eq!(
        map_result_control_hint(&app),
        "Esc Navigate to resolve this result"
    );
    app.set_input("keep this operator draft");
    assert_eq!(
        map_result_control_hint(&app),
        "Esc Navigate after finishing or clearing prompt draft"
    );
    app.clear_input();
    app.set_input_mode(InputMode::Navigate);
    let navigate_hint = map_result_control_hint(&app);
    assert!(navigate_hint.contains("u Use map"), "{navigate_hint}");
    assert!(navigate_hint.contains("n Use & Scan"), "{navigate_hint}");
    assert!(
        !navigate_hint.contains("Navigate to resolve"),
        "{navigate_hint}"
    );
}

#[test]
fn prompt_result_card_resolves_remapped_and_unbound_navigate_controls() {
    let mut remapped = V2Config::default();
    remapped.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
        context: "composer".to_string(),
        action: "navigate_mode".to_string(),
        bindings: vec!["ctrl+x".to_string()],
    }];
    let (_target, app) = unresolved_map_result_app(remapped);
    assert_eq!(
        map_result_control_hint(&app),
        "ctrl+x Navigate to resolve this result"
    );

    let mut unbound = V2Config::default();
    unbound.operator.keybindings = vec![kuzushi_core::config::KeybindingOverrideConfig {
        context: "composer".to_string(),
        action: "navigate_mode".to_string(),
        bindings: Vec::new(),
    }];
    let (_target, app) = unresolved_map_result_app(unbound);
    assert_eq!(
        map_result_control_hint(&app),
        "Navigate unbound · configure composer.navigate_mode"
    );
}

fn finding() -> Finding {
    Finding::new_tool(
        "semgrep",
        "rust/sql-injection",
        "src/auth/login.rs",
        17,
        None,
        Severity::High,
        "query reaches the database",
    )
}

fn verification() -> PersistedVerification {
    let mut verification = crate::test_support::test_empirical_verification(3);
    verification.harness_path = Some(".kuzushi/harness.rs".to_string());
    verification.crash_evidence = Some("reproduced SQL execution".to_string());
    verification.duration_ms = 420;
    verification.cost_usd = 0.07;
    verification.notes = vec!["isolated harness".to_string()];
    verification.verified_scan_id = Some("run-proof".to_string());
    verification.created_at = "2026-07-09T10:00:00Z".to_string();
    verification
}

#[test]
fn engagement_header_never_calls_an_unconfigured_model_configured() {
    assert_eq!(configured_model_label("unconfigured"), "unconfigured");
    assert_eq!(
        configured_model_label("openai:gpt-5 [auth missing]"),
        "configured openai:gpt-5 [auth missing]"
    );
}

#[test]
fn map_model_projects_durable_state_and_keeps_session_budget_in_the_header() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.session_mut().set_session_cost_usd_for_test(0.5);
    app.session_mut().set_session_budget_usd(Some(1.0));
    app.set_activity(Some(ActivitySession::for_phase(
        "unrelated-run",
        WorkflowPhase::Prove,
    )));

    let model = phase_cockpit_model_for_phase(&app, WorkflowPhase::Map);
    let PhaseCockpitBody::Map(map) = model.body else {
        panic!("expected map body");
    };

    assert_eq!(model.header.cost_usd, 0.5);
    assert_eq!(model.header.budget_usd, Some(1.0));
    assert_eq!(map.context.state, "missing");
    assert!(map
        .project
        .rows
        .iter()
        .any(|row| row.section == "context feed"));
    assert!(map.attack_surface.is_none());
    assert!(map.dfd.empty_hint.is_some());
}

#[test]
fn map_empty_state_is_independent_of_live_or_terminal_activity() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_activity(Some(ActivitySession::for_phase(
        "run-empty-map",
        WorkflowPhase::Map,
    )));

    let PhaseCockpitBody::Map(live) = phase_cockpit_model_for_phase(&app, WorkflowPhase::Map).body
    else {
        panic!("expected live map body");
    };
    assert_eq!(
        live.empty_hint,
        Some("select a target to map its durable security artifacts".to_string())
    );

    app.activity_mut().expect("activity").mark_terminal();
    let PhaseCockpitBody::Map(terminal) =
        phase_cockpit_model_for_phase(&app, WorkflowPhase::Map).body
    else {
        panic!("expected terminal map body");
    };
    assert_eq!(terminal, live);
}

#[test]
fn review_model_pairs_the_visible_queue_row_with_its_detail() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let finding = finding();
    *app.findings_mut() = vec![finding.clone()];
    *app.selected_finding_mut() = Some(finding);

    let model = phase_cockpit_model_for_phase(&app, WorkflowPhase::Review);
    let PhaseCockpitBody::Review(review) = model.body else {
        panic!("expected review body");
    };

    assert_eq!(review.review.rows.len(), 1);
    assert!(review.review.row_is_selected(0));
    assert_eq!(
        review
            .finding
            .as_ref()
            .and_then(|finding| finding.alias.as_deref()),
        Some("F-0001")
    );
}

#[test]
fn filtered_pinned_finding_is_disclosed_and_action_targets_stay_visible() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let pinned = finding();
    let visible = Finding::new_tool(
        "semgrep",
        "rust/log-forging",
        "src/log.rs",
        8,
        None,
        Severity::Low,
        "untrusted value reaches log output",
    );
    *app.findings_mut() = vec![pinned.clone(), visible];
    *app.selected_finding_mut() = Some(pinned.clone());
    app.set_active_findings_filter(Some("rank:low".to_string()));

    let PhaseCockpitBody::Review(review) =
        phase_cockpit_model_for_phase(&app, WorkflowPhase::Review).body
    else {
        panic!("expected review body");
    };
    assert_eq!(review.review.rows.len(), 1);
    assert_ne!(
        review.finding.expect("visible detail").fingerprint,
        pinned.fingerprint
    );
    let disclosure = review.selection_disclosure.expect("review disclosure");
    assert!(disclosure.message.contains("highlighted visible row"));
    assert_eq!(disclosure.filter, "rank:low");

    for phase in [WorkflowPhase::Prove, WorkflowPhase::Fix] {
        let disclosure = match phase_cockpit_model_for_phase(&app, phase).body {
            PhaseCockpitBody::Prove(model) => model.selection_disclosure,
            PhaseCockpitBody::Fix(model) => model.selection_disclosure,
            _ => unreachable!(),
        }
        .expect("actionable disclosure");
        assert!(disclosure
            .message
            .contains("actions target this displayed finding"));
        assert_eq!(disclosure.reveal_command, "findings");
    }
}

#[test]
fn prove_requires_persisted_verification_and_trace_for_replay() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let workspace = WorkspaceTarget::new(tmp.path()).expect("workspace");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    let mut selected = finding();
    selected.scan_id = Some("run-proof".to_string());
    *app.findings_mut() = vec![selected.clone()];
    *app.selected_finding_mut() = Some(selected.clone());

    let no_proof = phase_cockpit_model_for_phase(&app, WorkflowPhase::Prove);
    let PhaseCockpitBody::Prove(no_proof) = no_proof.body else {
        panic!("expected Prove body");
    };
    assert!(no_proof.proof.is_none());

    selected.verification = Some(verification());
    *app.findings_mut() = vec![selected.clone()];
    *app.selected_finding_mut() = Some(selected.clone());
    let persisted = phase_cockpit_model_for_phase(&app, WorkflowPhase::Prove);
    let PhaseCockpitBody::Prove(persisted) = persisted.body else {
        panic!("expected Prove body");
    };
    let proof = persisted.proof.expect("persisted verification");
    assert_eq!(proof.verdict, "exploited");
    assert_eq!(proof.provenance_run_id.as_deref(), Some("verify-run"));
    assert!(!proof.has_replay());
    assert!(!proof.requires_revalidation);

    let run_dir = kuzushi_core::run_dir(tmp.path(), "verify-run");
    std::fs::create_dir_all(&run_dir).expect("run dir");
    let writer = kuzushi_core::run_lifecycle::RunItemWriter::open(tmp.path(), "verify-run", None)
        .expect("lifecycle writer");
    writer
        .emit_and_flush(kuzushi_core::run_lifecycle::RunItemRecord::new(
            kuzushi_core::run_lifecycle::RunItemId::new(),
            kuzushi_core::run_lifecycle::RunItemSource::Workflow,
            kuzushi_core::run_lifecycle::RunItemV1::DiagnosticNotice {
                level: kuzushi_core::run_lifecycle::DiagnosticLevel::Info,
                message: kuzushi_core::run_lifecycle::SafeText::operator_visible(
                    "Verification replay available",
                ),
            },
        ))
        .expect("lifecycle item");
    app.hydrate_all_view_data_for_test();
    let replay = phase_cockpit_model_for_phase(&app, WorkflowPhase::Prove);
    let PhaseCockpitBody::Prove(replay) = replay.body else {
        panic!("expected Prove body");
    };
    assert!(replay.proof.expect("proof replay").has_replay());

    selected.scan_id = Some("run-after-proof".to_string());
    *app.findings_mut() = vec![selected.clone()];
    *app.selected_finding_mut() = Some(selected);
    let rescanned = phase_cockpit_model_for_phase(&app, WorkflowPhase::Prove);
    let PhaseCockpitBody::Prove(rescanned) = rescanned.body else {
        panic!("expected Prove body");
    };
    assert!(
        rescanned
            .proof
            .expect("prior verification")
            .requires_revalidation
    );
}

#[test]
fn fix_model_reuses_review_patch_graph_and_report_projections() {
    let mut app = ShellApp::new(V2Config::default(), None);
    let finding = finding();
    *app.findings_mut() = vec![finding.clone()];
    *app.selected_finding_mut() = Some(finding);
    app.engagement.set_pending_patch(PendingPatch {
        alias: "F-0001".to_string(),
        patch_run_id: "patch-fixture".to_string(),
        status: kuzushi_core::PatchStatus::Sound,
        rationale: "parameterize the query".to_string(),
        side_effect: None,
        diff: "- raw(query)\n+ bind(query)".to_string(),
        tests: vec![("unit".to_string(), "covers injection".to_string())],
        guardrail: None,
        staged_at: None,
    });

    let model = phase_cockpit_model_for_phase(&app, WorkflowPhase::Fix);
    let PhaseCockpitBody::Fix(fix) = model.body else {
        panic!("expected fix body");
    };

    assert_eq!(fix.findings.total, 1);
    assert_eq!(fix.review.total_count, 1);
    assert_eq!(fix.report.counts.total_findings, 1);
    assert_eq!(
        fix.patch.as_ref().map(|patch| patch.alias.as_str()),
        Some("F-0001")
    );
    assert!(fix.attack_tree.empty_hint.is_some());
    assert!(fix.dfd.empty_hint.is_some());
    assert_eq!(fix.export_command, "report");
}

#[test]
fn fix_model_projects_every_durable_patch_lifecycle_receipt() {
    let target = tempfile::tempdir().expect("target");
    let workspace = WorkspaceTarget::new(target.path()).expect("workspace");
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    crate::app::seed_pdf_phase_reference_fixture(
        &mut app,
        target.path(),
        crate::app::PhaseFixtureLifecycle::Settled,
    )
    .expect("fixture");
    let fingerprint = app
        .selected_finding()
        .as_ref()
        .expect("selected fixture finding")
        .fingerprint
        .clone();
    let finding_scan_id = app
        .selected_finding()
        .as_ref()
        .and_then(|finding| finding.scan_id.clone());
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).expect("store");
    let stable_fp = store
        .patch_lifecycle_stable_fp(&fingerprint)
        .expect("stable fingerprint");
    let mut record = PatchLifecycleRecord {
        application_id: "application-1".to_string(),
        stable_fp,
        fingerprint: fingerprint.clone(),
        finding_scan_id: finding_scan_id.clone(),
        patch_run_id: "patch-run-1".to_string(),
        target: target.path().display().to_string(),
        diff_hash: "diff-sha256".to_string(),
        base_commit: Some("base-commit".to_string()),
        touched_files: vec![PatchLifecycleFile {
            path: "src/auth/login.rs".to_string(),
            before_hash: Some("before".to_string()),
            after_hash: Some("after".to_string()),
        }],
        state: PatchLifecycleState::Applied,
        reverify_run_id: None,
        reverify_evidence: None,
        detail: Some("application receipt".to_string()),
        actor: "operator".to_string(),
        application_started_at: "2026-07-13T09:59:59Z".to_string(),
        applied_at: Some("2026-07-13T10:00:00Z".to_string()),
        updated_at: "2026-07-13T10:00:00Z".to_string(),
    };
    let cases = [
        (
            PatchLifecycleState::Applying,
            RemediationLifecycleStage::Applying,
        ),
        (
            PatchLifecycleState::ApplyFailed,
            RemediationLifecycleStage::ApplyFailed,
        ),
        (
            PatchLifecycleState::Applied,
            RemediationLifecycleStage::Applied,
        ),
        (
            PatchLifecycleState::ReverifyRunning,
            RemediationLifecycleStage::ReverifyRunning,
        ),
        (
            PatchLifecycleState::Verified,
            RemediationLifecycleStage::Verified,
        ),
        (
            PatchLifecycleState::StillVulnerable,
            RemediationLifecycleStage::StillVulnerable,
        ),
        (
            PatchLifecycleState::NotRediscovered,
            RemediationLifecycleStage::NotRediscovered,
        ),
        (
            PatchLifecycleState::Inconclusive,
            RemediationLifecycleStage::Inconclusive,
        ),
        (
            PatchLifecycleState::Failed,
            RemediationLifecycleStage::Failed,
        ),
        (
            PatchLifecycleState::Interrupted,
            RemediationLifecycleStage::Interrupted,
        ),
        (
            PatchLifecycleState::ChangedSinceApply,
            RemediationLifecycleStage::ChangedSinceApply,
        ),
    ];
    for (state, expected) in cases {
        record.state = state;
        record.reverify_run_id =
            (state == PatchLifecycleState::Verified).then(|| "reverify-run-1".to_string());
        record.reverify_evidence = None;
        if state == PatchLifecycleState::Verified {
            crate::test_support::attach_verified_patch_receipt(&workspace, &mut record);
        }
        store
            .insert_patch_lifecycle_record(&record)
            .expect("receipt");
        app.invalidate_finding_patch_truth(Some(&fingerprint));
        let target_revision = app
            .engagement
            .phase_target_snapshot()
            .and_then(|snapshot| snapshot.revision.clone());
        app.hydrate_view_keys_blocking(
            workspace.root(),
            vec![crate::app::ViewHydrationKey::FindingPatchTruth {
                fingerprint: fingerprint.clone(),
                finding_scan_id: finding_scan_id.clone(),
                target_revision,
            }],
        );
        let PhaseCockpitBody::Fix(fix) =
            phase_cockpit_model_for_phase(&app, WorkflowPhase::Fix).body
        else {
            panic!("expected fix body");
        };
        assert_eq!(fix.remediation.stage, expected);
        assert_eq!(fix.remediation.diff_hash.as_deref(), Some("diff-sha256"));
        assert_eq!(fix.remediation.touched_paths, ["src/auth/login.rs"]);
        if state == PatchLifecycleState::Applied {
            assert_eq!(
                fix.remediation.reverify_command.as_deref(),
                Some("run patch:reverify {\"applicationId\":\"application-1\"}")
            );
            assert_eq!(
                fix.remediation.reverify_control_hint.as_deref(),
                Some("Esc then v")
            );
        }
    }

    record.finding_scan_id = Some("prior-scan-generation".to_string());
    record.state = PatchLifecycleState::Verified;
    record.reverify_run_id = Some("prior-reverify-run".to_string());
    crate::test_support::attach_verified_patch_receipt(&workspace, &mut record);
    store
        .insert_patch_lifecycle_record(&record)
        .expect("prior-generation receipt");
    app.invalidate_finding_patch_truth(Some(&fingerprint));
    let target_revision = app
        .engagement
        .phase_target_snapshot()
        .and_then(|snapshot| snapshot.revision.clone());
    app.hydrate_view_keys_blocking(
        workspace.root(),
        vec![crate::app::ViewHydrationKey::FindingPatchTruth {
            fingerprint,
            finding_scan_id,
            target_revision,
        }],
    );
    let PhaseCockpitBody::Fix(fix) = phase_cockpit_model_for_phase(&app, WorkflowPhase::Fix).body
    else {
        panic!("expected fix body");
    };
    assert_eq!(
        fix.remediation.stage,
        RemediationLifecycleStage::PriorFindingGeneration
    );
    assert!(fix.remediation.reverify_command.is_none());
    assert!(fix
        .remediation
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("newer scan")));
}

#[test]
fn inspecting_another_page_does_not_forge_the_next_action() {
    let tmp = tempfile::tempdir().expect("tempdir");
    persist_imported_scan_attempt(tmp.path());
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(tmp.path().to_path_buf()));
    app.refresh_phase_attempt_projection();
    app.engagement.clear_phase();
    *app.findings_mut() = vec![finding()];
    assert_eq!(app.findings().len(), 1);
    assert_eq!(
        journey_model(&app).expect("journey").current,
        WorkflowPhase::Review
    );

    let model = phase_cockpit_model_for_phase(&app, WorkflowPhase::Map);

    assert_eq!(model.phase, WorkflowPhase::Map);
    assert!(
        model
            .header
            .next_action
            .contains("record terminal dispositions"),
        "{}",
        model.header.next_action
    );
    assert!(!model.header.next_action.contains("establish the grip"));
    assert!(
        !model.header.next_tools.contains("map target"),
        "{}",
        model.header.next_tools
    );
    let PhaseCockpitBody::Map(map) = model.body else {
        panic!("expected map body");
    };
    assert_eq!(map.empty_hint, None);
}

#[test]
fn legacy_restarted_result_card_requires_typed_run_evidence() {
    let target = tempfile::tempdir().expect("temp target");
    let completed = PhaseAttemptCompleted::new(
        WorkflowPhase::Scan,
        vec!["scan-run-1".to_string(), "scan-run-2".to_string()],
        PhaseTargetSnapshot::capture(target.path()),
        PhaseAttemptOutcome::Partial,
    )
    .with_receipt(PhaseAttemptReceipt {
        run_count: 2,
        elapsed_secs: 19,
        cost: "$0.4200".to_string(),
        changed_findings: 4,
        changed_artifacts: vec!["result.json".to_string(), "items.jsonl".to_string()],
        interaction_count: 2,
        rerun_specification: Some("run semgrep:scan".to_string()),
        actions: vec![
            PhaseResultAction::Select,
            PhaseResultAction::SelectAndContinue,
            PhaseResultAction::Open,
            PhaseResultAction::Refine,
        ],
        recommended_next: Some("acknowledge the partial Scan".to_string()),
    });
    append_phase_attempt_completed(target.path(), completed).unwrap();

    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(target.path().to_path_buf()));
    app.refresh_phase_attempt_projection();
    assert!(
        app.activity().is_none(),
        "fixture represents a restarted shell"
    );

    let model = phase_cockpit_model_for_phase(&app, WorkflowPhase::Scan);
    let card = model.header.result_card.expect("restart-safe result card");
    assert_eq!(
        card.actions,
        vec![
            PhaseResultAction::Open,
            PhaseResultAction::RunAgain,
            PhaseResultAction::Discard,
        ]
    );
    assert!(card.detail.contains("run receipt unavailable"));
    assert!(!card.detail.contains("$0.4200"));
    assert!(card.recommended.contains("open the failed run"));
    assert_eq!(card.control_hint, "Esc Navigate to resolve this result");
}

#[test]
fn phase_result_card_retains_canonical_keys_until_rendering() {
    use kuzushi_core::run_lifecycle::{RunCellKey, RunCellRoleV1, RunCellSourceV1, RunItemId};
    let key = RunCellKey {
        source: RunCellSourceV1::Item(RunItemId::new()),
        role: RunCellRoleV1::TerminalOutcome,
        ordinal: 0,
    };
    let presentation = crate::app::PhaseResultPresentation {
        attempt_id: "attempt-keyed".to_string(),
        outcome: "completed".to_string(),
        emphasis: crate::PhaseResultEmphasis::CompactDisposition,
        compact_summary: crate::PhaseResultCompactSummary {
            phase: WorkflowPhase::Scan,
            outcome: PhaseAttemptOutcome::Completed,
            run_count: 1,
            artifact_count: 0,
            changed_findings: 0,
            cost: None,
            revision_recorded: true,
            receipt_recorded: true,
        },
        detail_lines: vec!["Outcome · completed".to_string()],
        detail_rows: vec![crate::app::PhaseResultDetailRow {
            key: Some(key.clone()),
            disclosed_keys: std::collections::BTreeSet::new(),
            text: "Outcome · completed".to_string(),
        }],
        semantic_keys: std::collections::BTreeSet::from([key.clone()]),
        actions: vec![PhaseResultAction::Select],
        recommended_next: "inspect the result".to_string(),
    };
    let app = ShellApp::new(V2Config::default(), None);

    let card = phase_result_card_model(&app, WorkflowPhase::Scan, presentation);

    assert_eq!(card.semantic_keys, std::collections::BTreeSet::from([key]));
}

#[test]
fn compact_result_summary_keeps_known_cost_and_marks_unknown_accounting() {
    let mut summary = crate::PhaseResultCompactSummary {
        phase: WorkflowPhase::Map,
        outcome: PhaseAttemptOutcome::Completed,
        run_count: 2,
        artifact_count: 15,
        changed_findings: 0,
        cost: Some("$0.4200".to_string()),
        revision_recorded: true,
        receipt_recorded: true,
    };

    assert!(compact_result_summary(&summary).contains("$0.4200"));

    summary.cost = Some("cost not recorded".to_string());
    assert!(compact_result_summary(&summary).contains("⚠ cost not recorded"));
}

#[test]
fn card_model_drops_the_detail_row_that_duplicates_the_trailing_next() {
    // The strip renders `recommended` as its own `next:` row after the
    // control hint; the identical presentation detail row must not make
    // the recommendation print twice (J18 caught this live).
    let presentation = crate::app::PhaseResultPresentation {
        attempt_id: "attempt-failed".to_string(),
        outcome: "failed".to_string(),
        emphasis: crate::PhaseResultEmphasis::DominantDecision,
        compact_summary: crate::PhaseResultCompactSummary {
            phase: WorkflowPhase::Map,
            outcome: PhaseAttemptOutcome::Failed,
            run_count: 1,
            artifact_count: 0,
            changed_findings: 0,
            cost: None,
            revision_recorded: true,
            receipt_recorded: true,
        },
        detail_lines: vec![
            "1 canonical run reference(s)".to_string(),
            "next: open the failed run, adjust its input, or run it again".to_string(),
        ],
        detail_rows: [
            "1 canonical run reference(s)",
            "next: open the failed run, adjust its input, or run it again",
        ]
        .into_iter()
        .map(|text| crate::app::PhaseResultDetailRow {
            key: None,
            disclosed_keys: std::collections::BTreeSet::new(),
            text: text.to_string(),
        })
        .collect(),
        semantic_keys: std::collections::BTreeSet::new(),
        actions: vec![PhaseResultAction::Open],
        recommended_next: "open the failed run, adjust its input, or run it again".to_string(),
    };
    let app = ShellApp::new(V2Config::default(), None);

    let card = phase_result_card_model(&app, WorkflowPhase::Map, presentation);

    assert_eq!(
        card.detail_rows
            .iter()
            .filter(|row| row.text.starts_with("next: "))
            .count(),
        0,
        "recommendation must render exactly once, from `recommended`"
    );
    assert_eq!(card.detail_rows.len(), 1);
    assert_eq!(
        card.recommended,
        "open the failed run, adjust its input, or run it again"
    );
}

fn persist_imported_scan_attempt(target: &std::path::Path) {
    let snapshot = PhaseTargetSnapshot::capture(target);
    append_phase_checkpoint_skipped(
        target,
        PhaseCheckpointSkipped::new(WorkflowPhase::Map, snapshot.clone()),
    )
    .unwrap();
    crate::test_support::record_indexed_run(
        target,
        "imported-findings",
        "findings:import",
        serde_json::json!({
            "ok": true,
            "status": "completed",
            "summary": "findings imported",
            "data": {"count": 1}
        }),
    );
    let completed = crate::test_support::append_typed_attempt(
        target,
        WorkflowPhase::Scan,
        "imported-findings",
        PhaseAttemptOutcome::Completed,
    );
    crate::test_support::select_typed_attempt(target, &completed);
}

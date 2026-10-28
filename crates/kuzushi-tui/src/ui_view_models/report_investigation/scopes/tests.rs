use super::*;
use kuzushi_core::findings::{
    BatchOccurrenceReport, ContextCaseOccurrenceReport, IdentityFoldPolicy,
    ScopeStudyOccurrenceReport,
};
use kuzushi_core::workspace::{InvestigationContextCase, InvestigationReportEvidence};
use serde_json::{json, Value};

fn reference(digest: &str) -> Value {
    json!({"modelId":"recorded-model","revisionId":"recorded-revision","sha256":digest})
}

fn case(index: usize, reference: Option<Value>) -> InvestigationContextCase {
    let components = json!({"preparedInputSha256":"input","workspaceIdentity":"tree:owned",
        "configSha256":"configuration","descriptorSetSha256":"descriptors","loadedModules":[],
        "runtimeIdentity":{"backend":"native","configSha256":"runtime"},"threatModel":reference,
        "promptOverridesSha256":"prompts","houseRulesSha256":"rules","scopeSha256":"scope",
        "engineIdentity":{"kuzushiVersion":"fixture","requestedSelection":["semgrep"]}});
    let mut equivalence: kuzushi_core::capabilities::campaign::BatchEquivalenceKey =
        serde_json::from_value(json!({"sha256":"equivalence","components":components})).unwrap();
    equivalence.components.threat_model = reference;
    InvestigationContextCase {
        id: format!("boundary-{index}"),
        label: format!("Boundary {index}"),
        passes: 3,
        equivalence,
    }
}

fn receipt(references: Vec<Option<Value>>) -> ScopeStudyInvestigationReceipt {
    let cases: Vec<_> = references
        .into_iter()
        .enumerate()
        .map(|(index, reference)| case(index, reference))
        .collect();
    let occurrence = ScopeStudyOccurrenceReport {
        schema_version: 1,
        campaign_id: "scope-report".into(),
        plan_sha256: "plan".into(),
        cases: cases
            .iter()
            .map(|case| ContextCaseOccurrenceReport {
                id: case.id.clone(),
                label: case.label.clone(),
                threat_model_ref: case
                    .equivalence
                    .components
                    .threat_model
                    .clone()
                    .unwrap_or(Value::Null),
                occurrence: BatchOccurrenceReport {
                    schema_version: 1,
                    batch_id: "scope-report".into(),
                    equivalence_key: "conditions".into(),
                    identity_fold: IdentityFoldPolicy::default(),
                    planned: 3,
                    completed: 2,
                    failed: 1,
                    pending: 0,
                    gate: None,
                    trials: vec![],
                    rows: vec![],
                },
            })
            .collect(),
    };
    ScopeStudyInvestigationReceipt {
        investigation_brief: None,
        schema_version: 1,
        kind: "scope-study".into(),
        campaign_id: "scope-report".into(),
        plan_sha256: "plan".into(),
        workers: 1,
        scope_proposal_ref: kuzushi_core::workspace::ScanScopeProposalRef {
            proposal_id: "owned-scopes".into(),
            revision: 1,
            record_hash: "scope-record".into(),
        },
        inherited_threat_model_ref: Value::Null,
        context_selections: vec![],
        scan_selection: vec![],
        cases,
        scope: json!({}),
        unplanned_scope_ids: vec!["unplanned".into()],
        occurrence,
        evidence: InvestigationReportEvidence {
            observation_run_refs: vec![],
            observation_count: 0,
            finding_count: 0,
            reviewed_count: 0,
            confirmed_count: 0,
            review_decision_counts: Default::default(),
            reassessment_required_count: 0,
            attempts: vec![],
        },
        allowance: None,
        limitations: vec!["Recorded fixture limitation".into()],
    }
}

#[test]
fn identical_context_revision_is_shown_once_without_collapsing_work_or_source_limits() {
    let receipt = receipt(vec![Some(reference("digest-a")); 3]);
    let before = receipt.clone();
    let text = lines(&receipt, false, false).join("\n");
    assert!(text.contains("Frozen context revision for all 3 boundaries:"));
    assert_eq!(
        text.matches("Context: frozen recorded-model / recorded-revision")
            .count(),
        1
    );
    assert_eq!(
        text.matches("2 completed / 3 planned · 1 failed").count(),
        3
    );
    assert!(
        text.contains("Recorded on earlier source")
            && text.contains("no complete repository coverage claim")
    );
    assert!(text.contains("unplanned"));
    assert_eq!(receipt, before);
}

#[test]
fn report_prioritizes_allowance_and_coverage_over_repeated_context_and_boundaries() {
    let mut receipt = receipt(vec![Some(reference("digest-a")); 7]);
    receipt.evidence.reassessment_required_count = 1;
    receipt.scan_selection = receipt
        .cases
        .iter()
        .map(|case| kuzushi_core::workspace::InvestigationScanSelection {
            case_id: Some(case.id.clone()),
            parameters: serde_json::from_value(
                json!({"tasks":["semgrep"],"semgrepConfig":["p/owned"]}),
            )
            .unwrap(),
        })
        .collect();
    receipt.scope = receipt
        .cases
        .iter()
        .map(|case| {
            (
                case.id.clone(),
                json!({
                    "contextEvidence":{"status":"recorded","verification":{"verdict":"verified"}}
                }),
            )
        })
        .collect();
    let document = InvestigationReportDocument::ScopeStudy(receipt);
    let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
    let lines = selected_document_lines(&app, &document);
    assert!(lines[0].starts_with("Review: 1 finding needs source reassessment."));
    assert!(lines[1].starts_with("Scope study:"));
    let text = lines.join("\n");
    assert_eq!(
        text.matches("Context grounding: verified.").count(),
        1,
        "{text}"
    );
    assert!(text.contains("7 boundaries"));
    let position = |prefix: &str| {
        lines
            .iter()
            .position(|line| line.starts_with(prefix))
            .unwrap()
    };
    assert!(position("Allowance:") < position("Context grounding:"));
    assert!(position("Coverage:") < position("Boundary Boundary 0:"));
    app.router.report_mut().toggle_provenance();
    let detail_lines = selected_document_lines(&app, &document);
    let settings = detail_lines
        .iter()
        .position(|line| line.starts_with("Planned scan settings:"))
        .unwrap();
    let boundary = detail_lines
        .iter()
        .position(|line| line.starts_with("Boundary Boundary 0:"))
        .unwrap();
    assert!(settings < boundary);
    let details = detail_lines.join("\n");
    for index in 0..7 {
        assert!(details.contains(&format!("Boundary {index}: Context grounding: verified.")));
    }
}

#[test]
fn details_keep_each_boundarys_complete_context_reference_and_digest() {
    let receipt = receipt(vec![Some(reference("digest-a")); 2]);
    let text = lines(&receipt, true, true).join("\n");
    for label in ["Boundary 0", "Boundary 1"] {
        assert!(text.contains(&format!("{label} · Context reference:")));
    }
    assert_eq!(text.matches("\"sha256\":\"digest-a\"").count(), 2);
    assert!(text.contains("Study id: scope-report") && text.contains("Plan digest: plan"));
}

#[test]
fn equal_names_with_different_hashes_remain_separate() {
    let receipt = receipt(vec![
        Some(reference("digest-a")),
        Some(reference("digest-b")),
    ]);
    let text = lines(&receipt, false, true).join("\n");
    assert!(!text.contains("Frozen context revision for all"));
    assert_eq!(
        text.matches("Context: frozen recorded-model / recorded-revision")
            .count(),
        2
    );
    let detail = lines(&receipt, true, true).join("\n");
    assert!(detail.contains("digest-a") && detail.contains("digest-b"));
}

#[test]
fn absent_null_incomplete_and_single_contexts_are_not_a_common_revision() {
    for references in [
        vec![],
        vec![Some(reference("digest-a"))],
        vec![None, None],
        vec![Some(Value::Null); 2],
        vec![Some(json!({"modelId":"incomplete"})); 2],
        vec![Some(reference("digest-a")), None],
    ] {
        let receipt = receipt(references);
        assert!(!lines(&receipt, false, true)
            .join("\n")
            .contains("Frozen context revision for all"));
    }
}

use super::*;
use kuzushi_core::capabilities::campaign::{ScopeStudyDraft, ScopeStudyReceipt};
use kuzushi_core::workspace::ScanScopeProposalRef;
use serde_json::json;

fn config() -> BatchScanConfig {
    let mut config = BatchScanConfig::load(std::path::Path::new("/owned"), None);
    config.study.scan_input = Some(json!({"threatModelRef":null}));
    config.study.scope_draft = Some(ScopeStudyDraft {
        proposal_ref: ScanScopeProposalRef {
            proposal_id: "owned".into(),
            revision: 1,
            record_hash: "a".repeat(64),
        },
        cases: vec![ScopeStudyCaseInput {
            scope_id: "service".into(),
            passes: 3,
            threat_model_ref: Some(Value::Null),
        }],
    });
    config.scope_context.cursor = 1;
    config
}

fn compact(text: &str) -> String {
    text.chars().filter(|ch| !ch.is_whitespace()).collect()
}

#[test]
fn compact_boundary_facts_precede_notices_receipts_and_guidance() {
    let mut config = config();
    config.notice = Some("Recorded choice. ".repeat(30));
    let lines = detail(&config, 38);
    assert_eq!(lines[0], "Context association: omitted");
    assert_eq!(lines[1], "Plan: draft only.");
    assert_eq!(lines[2], "Boundary: service · 3 passes");
    let all = lines.join(" ");
    assert!(all.contains("Recorded choice."));
    let compact = compact(&all);
    assert!(compact.contains("explicitlyomitted"), "{all}");
    assert!(compact.contains("Selectiondoesnotactivate"), "{all}");
    assert!(
        compact.find("Drafteffectivecontext").unwrap() < compact.find("Enterinspects").unwrap()
    );
}

#[test]
fn common_context_keeps_unresolved_selection_and_guidance_honest() {
    let mut config = config();
    config.scope_context.cursor = 0;
    config.study.scan_input = None;
    config.notice = Some("Recorded notice".into());
    let lines = detail(&config, 120);
    assert_eq!(lines[0], "Common context for inheriting boundaries");
    assert_eq!(lines[1], "Plan: draft only.");
    let all = lines.join(" ");
    assert!(all.contains("unset; preparation must resolve it"));
    let compact = compact(&all);
    assert!(
        compact.contains("exactoverridesandexplicitomissionsremain"),
        "{all}"
    );
    assert!(compact.find("Commondraftcontext").unwrap() < compact.find("Enteropens").unwrap());
}

#[test]
fn prepared_status_requires_a_receipt_and_resets_with_the_plan() {
    let mut config = config();
    config.study.campaign_id = Some("unprepared-choice".into());
    assert_eq!(plan_status(&config), "Plan: draft only.");
    let receipt: ScopeStudyReceipt = serde_json::from_value(json!({
        "schemaVersion":1, "kind":"scope-study", "planPath":"/owned/plan.json", "requestedWorkers":1,
        "campaignId":"owned", "investigationId":"same-investigation", "planSha256":"sha256:owned",
        "workers":1, "jobCount":3, "scopeStudy":{
            "schemaVersion":1, "proposalRef":config.study.scope_draft.as_ref().unwrap().proposal_ref,
            "selections":[], "inheritedThreatModelRef":null, "cases":[], "unplannedScopeIds":[]
        }
    })).unwrap();
    config.study.scope_receipt = Some(receipt);
    assert_eq!(detail(&config, 38)[1], "Plan: prepared context recorded.");
    config.study.invalidate_plan();
    assert_eq!(detail(&config, 38)[1], "Plan: draft only.");
}

#[test]
fn long_boundary_names_cannot_hide_binding_and_preparation_state() {
    let mut config = config();
    let name = "Long boundary name ".repeat(20);
    config
        .scope_context
        .labels
        .insert("service".into(), name.clone());
    let lines = detail(&config, 38);
    assert_eq!(lines[0], "Context association: omitted");
    assert_eq!(lines[1], "Plan: draft only.");
    assert!(compact(&lines.join(" ")).contains(&compact(&name)));
}

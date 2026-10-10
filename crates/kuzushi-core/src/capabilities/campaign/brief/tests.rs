use super::*;
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use crate::{V2Config, WorkspaceTarget};
use serde_json::json;

mod guidance;
mod plans;

#[test]
fn revisions_preserve_exact_text_and_previous_reference() {
    let root = tempfile::tempdir().unwrap();
    let first = save_brief(
        root.path(),
        "repository",
        0,
        "Goal\nReview package policy.\n\nPriorities\nRetain owner questions.\n",
        &|| false,
    )
    .unwrap();
    let second = save_brief(
        root.path(),
        "repository",
        1,
        "Goal\nReview revised package policy.\n",
        &|| false,
    )
    .unwrap();
    assert_eq!(second.document.previous.as_ref(), Some(&first.reference));
    assert_eq!(load_brief(root.path(), &first.reference).unwrap(), first);
    assert_eq!(
        load_current_brief(root.path(), "repository").unwrap(),
        Some(second)
    );
    assert!(
        save_brief(root.path(), "repository", 1, "Lost update", &|| false)
            .unwrap_err()
            .to_string()
            .contains("revision changed")
    );
}

#[test]
fn concurrent_first_saves_have_one_winner() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_path_buf();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers = (0..2)
        .map(|id| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                save_brief(&path, "owned", 0, &format!("Owned goal {id}"), &|| false)
            })
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        load_current_brief(root.path(), "owned")
            .unwrap()
            .unwrap()
            .reference
            .revision,
        1
    );
}

#[test]
fn malformed_or_foreign_references_refuse_without_replacing_head() {
    let root = tempfile::tempdir().unwrap();
    let foreign = tempfile::tempdir().unwrap();
    let brief = save_brief(root.path(), "owned", 0, "Owned goal", &|| false).unwrap();
    let mut wrong = brief.reference.clone();
    wrong.object.size_bytes += 1;
    assert!(load_brief(root.path(), &wrong).is_err());
    wrong = brief.reference.clone();
    wrong.revision += 1;
    assert!(load_brief(root.path(), &wrong).is_err());
    let workspace = WorkspaceTarget::new(foreign.path()).unwrap();
    let original = WorkspaceTarget::new(root.path()).unwrap();
    let source = crate::content_store::ContentStore::open(original.objects_dir()).unwrap();
    let bytes = source
        .get_blob_bounded(&brief.reference.object.hash, 16384)
        .unwrap()
        .unwrap();
    crate::content_store::ContentStore::open(workspace.objects_dir())
        .unwrap()
        .put_blob(&bytes)
        .unwrap();
    crate::workspace::write_workspace_state_file(
        foreign.path(),
        ".kuzushi/v3/investigation-briefs/owned/revisions/1.json",
        &serde_json::to_vec(&brief.reference).unwrap(),
    )
    .unwrap();
    assert!(load_brief(foreign.path(), &brief.reference)
        .unwrap_err()
        .to_string()
        .contains("different target"));
    assert_eq!(
        load_current_brief(root.path(), "owned").unwrap(),
        Some(brief)
    );
}

#[test]
fn invalid_or_cancelled_saves_create_no_head() {
    let root = tempfile::tempdir().unwrap();
    for (id, text) in [
        ("../escape", "goal"),
        ("owned", "   "),
        ("owned", &"x".repeat(MAX_BRIEF_TEXT_BYTES + 1)),
    ] {
        assert!(save_brief(root.path(), id, 0, text, &|| false).is_err());
    }
    assert!(save_brief(root.path(), "owned", 0, "Goal", &|| true).is_err());
    assert!(load_current_brief(root.path(), "owned").unwrap().is_none());
}

#[test]
fn shared_dispatch_accepts_brief_options_without_work_or_map_truth() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let context = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let result = registry
        .execute_tool(
            "campaign:brief",
            json!({"mode":"save","expectedRevision":0,"text":"Owned goal\nReview policy"}),
            &context,
        )
        .unwrap();
    assert_eq!(result["data"]["workApproved"], false);
    assert_eq!(result["data"]["modelRequests"], 0);
    assert_eq!(result["data"]["findingVerdictsChanged"], false);
    assert!(
        !registry
            .resolve_tool("campaign:brief")
            .unwrap()
            .phase_result
    );
    assert!(registry
        .prepare_dispatch_input("campaign:brief", json!({"unknown":true}), &context, None)
        .is_err());
    assert!(registry
        .execute_tool(
            "campaign:brief",
            json!({"mode":"read","text":"Not a save"}),
            &context
        )
        .is_err());
}

#[test]
fn study_binds_an_exact_brief_without_changing_jobs_or_prompts() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "// Owned inert metadata\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let context = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let brief = save_brief(
        root.path(),
        "repository",
        0,
        "Review package policy",
        &|| false,
    )
    .unwrap();
    let input = json!({"campaignId":"brief-study","investigationId":"owned","briefRef":brief.reference,
        "scanInput":{"taskMode":"manual","tasks":["license-scan"],"threatModelRef":null}});
    let result = registry
        .execute_tool("campaign:study", input, &context)
        .unwrap();
    assert_eq!(result["data"]["jobCount"], 3);
    let plan = super::super::approved_work::read_bounded_plan(root.path(), "brief-study").unwrap();
    assert_eq!(plan["investigationBrief"], json!(brief));
    assert!(plan["baseInput"].get("briefRef").is_none());
    assert!(plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|job| job["input"].get("briefRef").is_none()));
    save_brief(
        root.path(),
        "repository",
        1,
        "A later operator goal",
        &|| false,
    )
    .unwrap();
    assert_eq!(
        load_plan_brief(root.path(), "brief-study").unwrap(),
        Some(brief)
    );
    assert!(!root
        .path()
        .join(".kuzushi/v3/campaigns/brief-study/queue.json")
        .exists());
    let mut forged = plan;
    forged["investigationBrief"]["document"]["text"] = json!("Forged goal");
    assert!(super::validate_plan(root.path(), &forged).is_err());
}

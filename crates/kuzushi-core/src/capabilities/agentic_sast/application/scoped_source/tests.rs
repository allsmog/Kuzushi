use super::*;
use crate::allowance::InvestigationWork;
use crate::runtime::scripted_fixture::account_scripted_runtime;
use crate::runtime::{AgentToolPolicyReceipt, READ_ONLY_ASK_TOOLS};
use crate::workspace::{
    accept_scan_scope_proposal, create_scan_scope_proposal, ProposedScanScope, ScanScopeDraft,
    ScopeCoverageApproval, WorkspaceTarget,
};
use std::sync::Mutex;

fn scope(id: &str, path: &str) -> ProposedScanScope {
    ProposedScanScope {
        id: id.into(),
        name: id.into(),
        paths: vec![path.into()],
        rationale: "Owned scope fixture".into(),
        shared_dependencies: Vec::new(),
        open_questions: Vec::new(),
    }
}

fn context<'a>(
    workspace: &'a WorkspaceTarget,
    config: &'a crate::V2Config,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

fn accepted_reference(workspace: &WorkspaceTarget, config: &crate::V2Config) -> ScanScopeRef {
    let ctx = context(workspace, config);
    let draft = ScanScopeDraft {
        schema_version: 1,
        scopes: vec![
            scope("app", "app"),
            scope("other", "other"),
            scope("integration", "shared"),
        ],
        shared_scope: Some(scope("shared", "shared")),
        shared_discovery: false,
        exclusions: Vec::new(),
    };
    let proposal = create_scan_scope_proposal(&ctx, Some(draft)).unwrap();
    let accepted = accept_scan_scope_proposal(
        &ctx,
        &proposal.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            exclusions: false,
            overlapping_discovery: false,
        },
    )
    .unwrap();
    ScanScopeRef {
        proposal: accepted.reference,
        scope_id: "app".into(),
    }
}

struct ScopedRuntime {
    requests: Mutex<Vec<AgentQueryRequest>>,
    acknowledges: bool,
}

impl AgentRuntime for ScopedRuntime {
    fn triage_finding_blocking(
        &self,
        _request: crate::runtime::TriageRequest,
    ) -> Result<crate::findings::TriageOutcome> {
        unreachable!("owned scoped fixture does not triage")
    }

    fn authorize_tool_policy_blocking(
        &self,
        auth: &AgentToolPolicyAuthorization,
    ) -> Result<AgentToolPolicyReceipt> {
        anyhow::ensure!(
            self.acknowledges,
            "fixture runtime cannot acknowledge membership"
        );
        Ok(AgentToolPolicyReceipt {
            protocol_version: auth.protocol_version,
            policy_id: auth.policy_id.clone(),
            effective_tools: READ_ONLY_ASK_TOOLS.map(String::from).to_vec(),
            read_roots: auth.policy.mcp_read_roots.clone(),
            write_shell_tools_mounted: false,
            mcp_tools_mounted: false,
            read_scope_sha256: auth
                .policy
                .read_scope
                .as_ref()
                .map(|scope| scope.sha256.clone()),
        })
    }

    fn query_blocking(
        &self,
        request: AgentQueryRequest,
    ) -> Result<crate::runtime::AgentQueryResponse> {
        self.requests.lock().unwrap().push(request);
        let findings = ["app/[route]/reader.rs", "shared/context.rs", "other/unapproved.rs"].map(|path| json!({
            "ruleId":"labeled-fixture", "title":"Labeled scope observation", "filePath":path,
            "startLine":1, "severity":"INFO", "message":"Owned source-only fixture; no defect claimed"}));
        Ok(crate::runtime::AgentQueryResponse {
            structured: Some(json!({"findings":findings})),
            ..Default::default()
        })
    }
}

fn source_fixture(root: &Path) {
    for directory in ["app/[route]", "shared", "other"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    for (path, text) in [
        ("app/[route]/reader.rs", "OWNED_DISCOVERY"),
        ("shared/context.rs", "OWNED_CONTEXT"),
        ("other/unapproved.rs", "UNAPPROVED_SOURCE"),
    ] {
        std::fs::write(root.join(path), text).unwrap();
    }
}

#[test]
fn exact_scope_inherits_context_but_does_not_import_context_or_unapproved_findings() {
    let root = tempfile::tempdir().unwrap();
    source_fixture(root.path());
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let reference = accepted_reference(&workspace, &config);
    let runtime = ScopedRuntime {
        requests: Mutex::new(Vec::new()),
        acknowledges: true,
    };
    let store = crate::findings::FindingStore::open(workspace.findings_db_path()).unwrap();
    let mut ctx = context(&workspace, &config);
    ctx.findings_store = Some(&store);
    let accounted = account_scripted_runtime(&ctx, &runtime, InvestigationWork::Discovery, 1);
    let result = crate::ModuleRegistry::with_v2_builtins()
        .execute_tool_with_runtime(
            "agentic-sast:scan",
            json!({"scanScopeRef":reference,"threatModelRef":null,"scanContextRef":null}),
            &ctx,
            Some(&accounted),
        )
        .unwrap();
    assert_eq!(result["data"]["count"], 1);
    assert_eq!(
        result["data"]["outOfScopeObservations"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(result["data"]["scope"]["inheritedContextFiles"], 1);
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].tool_policy.read_scope.as_ref().unwrap().files,
        vec!["app/[route]/reader.rs", "shared/context.rs"]
    );
    assert!(requests[0]
        .prompt
        .contains(&crate::runbooks::untrusted::render_untrusted_repo_block(
            "shared/context.rs",
            "OWNED_CONTEXT"
        )));
    assert!(!requests[0].prompt.contains("UNAPPROVED%5FSOURCE"));
    assert_eq!(store.list_findings(10).unwrap().len(), 1);
    let receipt = crate::SpendLimiter::open(workspace.findings_db_path())
        .unwrap()
        .allowance_snapshot(
            &accounted
                .allowance_binding()
                .unwrap()
                .work()
                .investigation_id,
        )
        .unwrap();
    assert_eq!(receipt.committed_calls, 1);
    assert_eq!(receipt.unresolved_calls, 0);
    assert!(!receipt.cost.is_complete());
}

#[test]
fn unsupported_scoped_runtime_starts_no_model_query() {
    let root = tempfile::tempdir().unwrap();
    source_fixture(root.path());
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let reference = accepted_reference(&workspace, &config);
    let runtime = ScopedRuntime {
        requests: Mutex::new(Vec::new()),
        acknowledges: false,
    };
    let store = crate::findings::FindingStore::open(workspace.findings_db_path()).unwrap();
    let mut ctx = context(&workspace, &config);
    ctx.findings_store = Some(&store);
    let accounted = account_scripted_runtime(&ctx, &runtime, InvestigationWork::Discovery, 1);
    let error = crate::ModuleRegistry::with_v2_builtins()
        .execute_tool_with_runtime(
            "agentic-sast:scan",
            json!({"scanScopeRef":reference,"threatModelRef":null,"scanContextRef":null}),
            &ctx,
            Some(&accounted),
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("no scoped model request started"),
        "{error:#}"
    );
    assert!(runtime.requests.lock().unwrap().is_empty());
    let receipt = crate::SpendLimiter::open(workspace.findings_db_path())
        .unwrap()
        .allowance_snapshot(
            &accounted
                .allowance_binding()
                .unwrap()
                .work()
                .investigation_id,
        )
        .unwrap();
    assert_eq!(receipt.committed_calls, 0);
    assert_eq!(receipt.unresolved_calls, 0);
}

#[test]
fn changed_accepted_source_starts_no_model_query() {
    let root = tempfile::tempdir().unwrap();
    source_fixture(root.path());
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let reference = accepted_reference(&workspace, &config);
    std::fs::write(root.path().join("app/[route]/reader.rs"), "CHANGED_SOURCE").unwrap();
    let runtime = ScopedRuntime {
        requests: Mutex::new(Vec::new()),
        acknowledges: true,
    };
    assert!(run_agentic_sast_report(
        &json!({"scanScopeRef":reference}),
        &context(&workspace, &config),
        Some(&runtime)
    )
    .is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn incompatible_scope_controls_are_refused_without_replacing_selected_work() {
    for input in [
        json!({"strategy":"chunked"}),
        json!({"mcps":true}),
        json!({"includePatterns":["other/**"]}),
        json!({"excludePatterns":["app/**"]}),
    ] {
        assert!(validate_agentic_scope_options(&input).is_err());
    }
}

#[test]
fn a_target_override_cannot_rebind_the_accepted_file_membership() {
    let root = tempfile::tempdir().unwrap();
    source_fixture(root.path());
    let other = tempfile::tempdir().unwrap();
    source_fixture(other.path());
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let reference = accepted_reference(&workspace, &config);
    let runtime = ScopedRuntime {
        requests: Mutex::new(Vec::new()),
        acknowledges: true,
    };
    let error = run_agentic_sast_report(
        &json!({"target":other.path(),"scanScopeRef":reference}),
        &context(&workspace, &config),
        Some(&runtime),
    )
    .unwrap_err();
    assert!(error.to_string().contains("cannot rebind its files"));
    assert!(runtime.requests.lock().unwrap().is_empty());
}

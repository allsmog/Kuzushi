use super::*;
use serde_json::{json, Value};

struct SourceEngineFixture {
    _target: tempfile::TempDir,
    _adapter: tempfile::TempDir,
    workspace: WorkspaceTarget,
    config: V2Config,
    allowance: Value,
    calls: u32,
}

impl SourceEngineFixture {
    fn new(
        prepare_source: impl FnOnce(&PathBuf),
        build_bridge: fn(&PathBuf) -> PathBuf,
        calls: u32,
    ) -> Self {
        let target = tempfile::tempdir().unwrap();
        let adapter = tempfile::tempdir().unwrap();
        prepare_source(&target.path().to_path_buf());
        let raw = build_bridge(&adapter.path().to_path_buf());
        let bridge = prepared_dispatch::admitted_fixture_script_bridge(
            adapter.path(),
            "source-engine",
            &raw,
        );
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-4.1".into()),
            runtime: RuntimeConfig {
                kind: RuntimeKind::LangGraph,
                api_key_env: "OPENAI_API_KEY".into(),
                langgraph_bridge_command: Some(vec![bridge.display().to_string()]),
                ..Default::default()
            },
            ..Default::default()
        };
        prepared_dispatch::build_fixture_context(&config, &workspace);
        let allowance =
            prepared_dispatch::approve_model_work_with_limits(&config, &workspace, calls, 0);
        Self {
            _target: target,
            _adapter: adapter,
            workspace,
            config,
            allowance,
            calls,
        }
    }

    fn app(&self) -> ShellApp {
        ShellApp::new(self.config.clone(), Some(&self.workspace))
    }

    fn input(&self, input: Value) -> Option<String> {
        self.input_for_work("one-tool", input)
    }

    fn input_for_work(&self, work: &str, mut input: Value) -> Option<String> {
        let mut reference = self.allowance.clone();
        reference["workId"] = json!(work);
        input["allowanceRef"] = reference;
        Some(input.to_string())
    }

    fn assert_consumption(&self, expected: u32) {
        let ledger = kuzushi_core::SpendLimiter::open(self.workspace.findings_db_path()).unwrap();
        let snapshot = ledger.allowance_snapshot("dispatch-fixture").unwrap();
        assert_eq!(snapshot.committed_calls, expected, "{snapshot:?}");
        assert_eq!(snapshot.unresolved_calls, 0, "{snapshot:?}");
        assert_eq!(snapshot.limits.max_provider_calls, self.calls);
        assert_eq!(snapshot.protected_review_remaining(), 0);
    }
}

fn write_source(root: &Path, name: &str, text: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn record_variant_seed_decision(workspace: &WorkspaceTarget, fingerprint: &str) {
    use kuzushi_core::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let finding = store
        .get_finding_by_fingerprint(fingerprint)
        .unwrap()
        .unwrap();
    store
        .append_user_review_decision(
            finding.id.unwrap(),
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Scripted operator acceptance of an owned fixture seed".into(),
                dismiss_reason: None,
                actor: Some("scripted operator".into()),
            },
        )
        .unwrap();
}

#[test]
fn run_command_dispatches_variant_hunt_through_langgraph_runtime_bridge_and_persists() {
    let _env_lock = env_test_lock();
    let _api_key = EnvVarGuard::set("OPENAI_API_KEY", "test-key");
    let fixture = SourceEngineFixture::new(
        |root| {
            write_source(root, "src/app.ts", "exec(req.body.cmd)\n");
            write_source(root, "src/other.ts", "exec(req.body.other)\n");
        },
        fake_variant_bridge,
        1,
    );
    let fingerprint = seed_true_positive_finding(&fixture.workspace);
    record_variant_seed_decision(&fixture.workspace, &fingerprint);
    let mut app = fixture.app();
    run_command(&mut app, ShellCommand::Use("variant".into()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("variant:hunt".into()),
            input: fixture.input(json!({"fingerprint":fingerprint,"maxFindings":5})),
        },
    );
    drain_tool(&mut app);
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(
        app.log_lines().iter().any(|line| line.prefix == "result"
            && line.body.starts_with("Related source observations.")
            && line
                .body
                .contains("each observation needs independent review")),
        "{:?}",
        app.log_lines()
    );
    let store = FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    assert!(store
        .list_findings(10)
        .unwrap()
        .iter()
        .any(|finding| finding.tool == "variant-analysis"));
    let run = &app.activity().unwrap().run_id;
    let projection =
        kuzushi_core::run_lifecycle::load_run_projection(fixture.workspace.root(), run).unwrap();
    let summaries = projection.presentation_hydration.verified_summaries();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].status, "partial");
    fixture.assert_consumption(fixture.calls);
}

#[test]
fn run_command_dispatches_taint_iris_through_langgraph_runtime_bridge_and_persists() {
    let _env_lock = env_test_lock();
    let _api_key = EnvVarGuard::set("OPENAI_API_KEY", "test-key");
    let fixture = SourceEngineFixture::new(
        |root| {
            write_source(root, "src/db.ts", "db.query(req.query.q)\n");
        },
        fake_taint_iris_bridge,
        1,
    );
    let mut app = fixture.app();
    app.session_mut().set_trusted_workflow_auto_accept(true);
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("taint-iris:hunt".into()),
            input: fixture.input(json!({"maxFindings":5,"mcps":false})),
        },
    );
    drain_chain_with_auto_reuse(&mut app);
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.domain().taint_flow().is_none());
    assert!(
        app.log_lines().iter().any(|line| line.prefix == "result"
            && line.body.contains("Taint IRIS Next")
            && line.body.contains("findings: 1")),
        "{:?}",
        app.log_lines()
    );
    let store = FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "taint-iris-next");
    fixture.assert_consumption(fixture.calls);
}

fn taint_next_fixture(calls: u32) -> SourceEngineFixture {
    SourceEngineFixture::new(
        |root| {
            write_source(
                root,
                "package.json",
                r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
            );
            write_source(
                root,
                "src/routes.ts",
                "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
            );
        },
        fake_taint_iris_next_bridge,
        calls,
    )
}

#[test]
fn missing_model_catalog_cannot_borrow_the_final_hunt_allowance() {
    let _env_lock = env_test_lock();
    let _api_key = EnvVarGuard::set("OPENAI_API_KEY", "test-key");
    let fixture = taint_next_fixture(1);
    let mut app = fixture.app();
    app.session_mut().set_trusted_workflow_auto_accept(true);
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("taint-iris-next:hunt".into()),
            input: fixture.input_for_work("hunt", json!({"mode":"hunt","maxCatalogEntries":3})),
        },
    );
    drain_chain_with_auto_reuse(&mut app);
    assert!(app.log_lines().iter().any(|line| line.prefix == "result"
        && line
            .body
            .contains("taint-iris-next:catalog needs an approved investigation allowance")));
    assert!(!app.log_lines().iter().any(
        |line| line.prefix == "tool" && line.body.starts_with("running taint-iris-next:hunt ")
    ));
    let store = FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    assert!(store.list_all_findings().unwrap().is_empty());
    fixture.assert_consumption(0);
}

#[test]
fn run_command_dispatches_legacy_taint_iris_next_hunt_through_langgraph_runtime_bridge_and_persists(
) {
    let _env_lock = env_test_lock();
    let _api_key = EnvVarGuard::set("OPENAI_API_KEY", "test-key");
    let fixture = taint_next_fixture(2);
    let mut app = fixture.app();
    app.session_mut().set_trusted_workflow_auto_accept(true);
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("taint-iris-next:catalog".into()),
            input: fixture.input_for_work("catalog", json!({})),
        },
    );
    drain_chain_with_auto_reuse(&mut app);
    fixture.assert_consumption(1);
    assert!(fixture
        .workspace
        .root()
        .join(".kuzushi/taint-iris-next-catalog.json")
        .exists());
    run_command(&mut app, ShellCommand::Use("taint-iris-next".into()));
    run_command(&mut app, ShellCommand::RunTool {
        tool: Some("taint-iris-next:hunt".into()),
        input: fixture.input_for_work("hunt", json!({"mode":"hunt","maxCatalogEntries":3,"maxAgentFindings":5,"minEvidenceLevel":"candidate"})),
    });
    drain_chain_with_auto_reuse(&mut app);
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(app.domain().taint_flow().is_none());
    assert!(
        app.log_lines().iter().any(|line| line.prefix == "result"
            && line.body.contains("Taint IRIS Next")
            && line.body.contains("hunt complete")),
        "{:?}",
        app.log_lines()
    );
    let store = FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "taint-iris-next");
    fixture.assert_consumption(fixture.calls);
}

#[test]
fn run_command_dispatches_carlini_threat_hunt_through_langgraph_runtime_bridge_and_persists() {
    let _env_lock = env_test_lock();
    let _api_key = EnvVarGuard::set("OPENAI_API_KEY", "test-key");
    let fixture = SourceEngineFixture::new(
        |root| {
            write_source(root, "src/app.ts", "res.send(`<p>${req.query.name}</p>`)\n");
            write_carlini_threat_model_fixture(root);
        },
        fake_carlini_bridge,
        1,
    );
    let mut app = fixture.app();
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("carlini-threat-hunt:run".into()),
            input: fixture.input(json!({"maxActors":1,"runsPerActor":1})),
        },
    );
    drain_chain_with_auto_reuse(&mut app);
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(
        app.log_lines()
            .iter()
            .any(|line| line.prefix == "result"
                && line.body.contains("carlini-threat-hunt: 1 finding")),
        "{:?}",
        app.log_lines()
    );
    let store = FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "carlini-threat-hunt");
    assert_eq!(
        findings[0].actor_fingerprint.as_deref(),
        Some("carlini-threat-hunt:Authenticated_User:0")
    );
    fixture.assert_consumption(fixture.calls);
}

#[test]
fn run_command_dispatches_systems_hunt_through_langgraph_runtime_bridge_and_persists() {
    let _env_lock = env_test_lock();
    let _api_key = EnvVarGuard::set("OPENAI_API_KEY", "test-key");
    let fixture = SourceEngineFixture::new(write_systems_hunt_fixture, fake_systems_hunt_bridge, 3);
    let mut app = fixture.app();
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("systems-hunt:systems-hunt".into()),
            input: fixture.input(json!({"maxFindings":5})),
        },
    );
    drain_tool(&mut app);
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(
        app.log_lines()
            .iter()
            .any(|line| line.prefix == "result" && line.body.contains("systems-hunt: 1 finding")),
        "{:?}",
        app.log_lines()
    );
    let store = FindingStore::open(fixture.workspace.findings_db_path()).unwrap();
    let findings = store.list_findings(10).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "systems-hunt");
    fixture.assert_consumption(fixture.calls);
}

#[test]
fn run_command_dispatches_x_ray_run_through_langgraph_runtime_bridge() {
    let _env_lock = env_test_lock();
    let _api_key = EnvVarGuard::set("OPENAI_API_KEY", "test-key");
    let fixture = SourceEngineFixture::new(
        |root| {
            write_source(root, "README.md", "# app\n");
        },
        fake_x_ray_bridge,
        1,
    );
    let mut app = fixture.app();
    run_command(&mut app, ShellCommand::Use("x-ray".into()));
    run_command(
        &mut app,
        ShellCommand::RunTool {
            tool: Some("x-ray:run".into()),
            input: fixture.input(json!({})),
        },
    );
    press_key(
        &mut app,
        KeyEvent::new(KeyCode::Char('y'), KeyModifiers::empty()),
    );
    drain_tool(&mut app);
    assert_eq!(app.shell_view(), ShellView::Activity);
    assert!(
        app.log_lines()
            .iter()
            .any(|line| line.prefix == "result" && line.body.contains("x-ray:run complete")),
        "{:?}",
        app.log_lines()
    );
    assert!(fixture.workspace.root().join("x-ray/x-ray.md").exists());
    assert!(fixture
        .workspace
        .root()
        .join("x-ray/architecture.svg")
        .exists());
    fixture.assert_consumption(fixture.calls);
}

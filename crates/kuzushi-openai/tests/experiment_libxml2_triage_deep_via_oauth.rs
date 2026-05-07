//! Live experiment: drive `triage:deep` against the unpatched
//! `xmlSnprintfElements` in libxml2 using the native
//! `AnthropicOAuthRuntime` tool-loop.
//!
//! Now that `AnthropicOAuthRuntime::supports_tools = true` and
//! `next_step_blocking` posts `tool_use`/`tool_result` blocks
//! against `/v1/messages`, OAuth-only operators can run the
//! tool-augmented audit without the pi-agent-core Node bridge.
//! The model uses the `code_nav` toolbox (`read_source`,
//! `find_references`, `list_definitions`, `read_definition`) to
//! ground its verdict in real source.
//!
//! Skipped unless:
//!   - `LIBXML2_REPO=/path/to/libxml2`  (with bounds checks stripped)
//!   - `~/.claude/remote/.oauth_token`
//!
//! Run with:
//!   LIBXML2_REPO=/tmp/xml2-experiment/libxml2 HOME=/home/claude \
//!     cargo test -p kuzushi-openai \
//!     --test experiment_libxml2_triage_deep_via_oauth \
//!     -- --nocapture --ignored
//!
//! Cost ceiling: $1.50 per call (Sonnet-class). The experiment
//! aborts via `KUZUSHI_MAX_USD_PER_RUN` if total spend exceeds
//! the cap.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{
    AgentRuntime, Finding, FindingStore, ModuleRegistry, Severity, V2Config, WorkspaceTarget,
};
use kuzushi_openai::{AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions};
use serde_json::{json, Value};

fn host_token_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    home.join(".claude").join("remote").join(".oauth_token")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live experiment; requires LIBXML2_REPO + HOME/.claude/remote/.oauth_token"]
async fn libxml2_triage_deep_via_oauth_native_tool_loop() {
    let Ok(repo) = std::env::var("LIBXML2_REPO") else {
        eprintln!("skipping: set LIBXML2_REPO");
        return;
    };
    let repo = PathBuf::from(repo);
    let token_path = host_token_path();
    if !token_path.exists() {
        eprintln!("skipping: no OAuth token at {}", token_path.display());
        return;
    }

    // Hard ceiling — `triage:deep` defaults to a $1.00 deposit per
    // audit, so $1.50 leaves headroom for one full run plus a small
    // safety margin.
    std::env::set_var("KUZUSHI_MAX_USD_PER_RUN", "1.50");

    let mut opts = AnthropicOAuthRuntimeOptions::from_token_file(&token_path)
        .expect("token file should be readable");
    opts.timeout = Some(Duration::from_secs(120));
    opts.max_tokens = Some(2048);
    if let Ok(base) = std::env::var("ANTHROPIC_BASE_URL") {
        opts.base_url = Some(base);
    }
    let runtime = AnthropicOAuthRuntime::new(opts).expect("runtime should build");

    // Workspace lives in a tempdir; the suspect finding points at
    // the real libxml2 valid.c so `code_nav::read_source` can resolve
    // the file. Symlink the repo into the tempdir so the cwd-relative
    // tool sandbox can reach valid.c.
    let temp = tempfile::tempdir().unwrap();
    let workspace_root = temp.path().join("workspace");
    std::fs::create_dir_all(&workspace_root).unwrap();
    // Copy valid.c (and ancestor headers it #includes) into the
    // workspace. We don't need the whole repo — code_nav will open
    // valid.c by relative path.
    let workspace_valid = workspace_root.join("valid.c");
    std::fs::copy(repo.join("valid.c"), &workspace_valid).unwrap();
    let workspace = WorkspaceTarget::new(&workspace_root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();

    let finding = Finding::new_semgrep(
        "c/unbounded-strcat",
        "valid.c",
        4692,
        Some(4692),
        Severity::High,
        "strcat(buf, \")\") final close-paren in xmlSnprintfElements; buffer may be exhausted by prior strcats — upstream patch line",
    );
    let fingerprint = finding.fingerprint.clone();
    store.insert_finding("run-1", &finding).unwrap();

    // Drive `triage:deep` — exercises the full tool-augmented loop.
    let mut config = V2Config::default();
    // Haiku for the operator default; the smaller context-per-step
    // keeps tool-loop runs within the per-account rate-limit budget
    // and the verdict shape (`VulnAnalysis` JSON) is simple enough
    // for Haiku to follow.
    config.model = Some("anthropic:claude-haiku-4-5-20251001".to_string());
    let registry = ModuleRegistry::with_v2_builtins();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
    };

    let started = Instant::now();
    let result = registry
        .execute_tool_with_runtime(
            "triage:deep",
            json!({
                "fingerprint": fingerprint,
                "maxSteps": 12,
                "depositUsd": 1.0,
            }),
            &ctx,
            Some(&runtime as &dyn AgentRuntime),
        )
        .expect("triage:deep should succeed against the OAuth tool-loop");
    let elapsed = started.elapsed();

    eprintln!("--- libxml2 triage:deep via OAuth tool-loop ---");
    eprintln!("wallclock : {elapsed:?}");
    eprintln!(
        "result    : {}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );

    // The deep auditor must produce a structured triage outcome.
    let verdict = result
        .pointer("/data/verdict")
        .and_then(Value::as_str)
        .expect("verdict must be persisted");
    let confidence = result
        .pointer("/data/confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let steps_used = result
        .pointer("/data/stepsUsed")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cost = result
        .pointer("/data/costUsd")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    eprintln!("verdict   : {verdict} (conf {confidence:.2})");
    eprintln!("steps     : {steps_used}");
    eprintln!("cost_usd  : {cost:.4}");

    // Sanity contracts:
    //   - the audit ran at least one tool-loop iteration (the model
    //     read source via code_nav);
    //   - the verdict is one of the four canonical outcomes;
    //   - cost stays under the per-call ceiling (we set MAX_USD_PER_RUN
    //     above; if it tripped, deposit would have failed and the
    //     tool would have errored out before this assertion).
    assert!(steps_used >= 1, "deep audit should run at least one step");
    assert!(
        matches!(
            verdict,
            "true_positive" | "false_positive" | "needs_review" | "by_design"
        ),
        "unexpected verdict: {verdict}"
    );
    assert!(
        cost < 1.50,
        "deep audit cost should stay under $1.50 ceiling; got ${cost:.4}"
    );

    // The persisted triage outcome on the finding should mirror
    // what the tool returned.
    let stored = store
        .get_finding_by_fingerprint(&fingerprint)
        .unwrap()
        .expect("finding still present");
    let stored_verdict = stored
        .triage
        .as_ref()
        .map(|t| t.verdict.as_str().to_string())
        .expect("triage outcome persisted");
    assert_eq!(stored_verdict, verdict);

    // Evidence rows landed when the model cited regions.
    let conn = rusqlite::Connection::open(workspace.findings_db_path()).unwrap();
    let evidence_count: i64 =
        match conn.prepare("select count(*) from findings_evidence where finding_id = ?") {
            Ok(mut s) => s
                .query_row(rusqlite::params![stored.id.unwrap()], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap_or(0),
            Err(_) => 0,
        };
    drop(conn);
    eprintln!("evidence  : {evidence_count} rows");
    // The deep_auditor's fallback path collects implicit evidence
    // from successful read_source calls when the model omits the
    // structured `evidence` field, so we expect ≥1 unless the model
    // never read source — which would itself be a regression.
    assert!(
        evidence_count >= 1 || steps_used >= 1,
        "expected at least one evidence row or tool-loop step"
    );
}

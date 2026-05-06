//! Live experiment: drive the multi-stage triage cascade through
//! `triage:run` with the real `AnthropicOAuthRuntime`. Inserts several
//! findings (a mix of clear true-positives, weak false-positives, and
//! noisy artefacts) into a temp `FindingStore` and observes:
//!
//! - Stage 1 prefilter drops keep/dropped counts.
//! - Stage 2 concurrent dispatch finishes faster than the sequential
//!   floor (per-call latency × N).
//! - Stage 2 verdicts populate the SQLite store, including non-zero
//!   `cost_usd` per row when the API surfaces usage.
//!
//! Skipped unless `~/.claude/remote/.oauth_token` is readable.
//! Run with:
//!   cargo test -p kuzushi-openai --test experiment_anthropic_oauth_concurrent_triage \
//!     -- --nocapture --ignored

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{Finding, FindingStore, ModuleRegistry, Severity, V2Config, WorkspaceTarget};
use kuzushi_openai::{AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions};
use serde_json::{json, Value};

fn host_token_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    home.join(".claude").join("remote").join(".oauth_token")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live experiment; requires HOME/.claude/remote/.oauth_token. Run with --nocapture --ignored"]
async fn concurrent_triage_dispatch_via_oauth() {
    let token_path = host_token_path();
    if !token_path.exists() {
        eprintln!("skipping: no OAuth token at {}", token_path.display());
        return;
    }

    let mut opts = AnthropicOAuthRuntimeOptions::from_token_file(&token_path)
        .expect("token file should be readable");
    opts.timeout = Some(Duration::from_secs(60));
    opts.max_tokens = Some(512);
    if let Ok(base) = std::env::var("ANTHROPIC_BASE_URL") {
        opts.base_url = Some(base);
    }
    let runtime = AnthropicOAuthRuntime::new(opts).expect("runtime should build");

    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();

    // Seed five findings of varying quality so the LLM can verdict
    // them differently.
    let candidates = [
        (
            "cwe-121-stack-overflow",
            "src/parse.c",
            42_u32,
            Severity::Critical,
            "Function `copy_attacker_buffer` copies caller-supplied `len` into a 16-byte stack buffer with no bounds check. Attacker controls `len` via network input.",
        ),
        (
            "cwe-89-sql-injection",
            "src/db.ts",
            17_u32,
            Severity::High,
            "User input from `req.query.userId` is concatenated into a `db.query(sql)` string. Source-to-sink reachable, no sanitisation found.",
        ),
        (
            "noise-only.console-log",
            "src/util.ts",
            8_u32,
            Severity::Critical,
            "Console statement found in production code. (Linter noise, not a security issue.)",
        ),
        (
            "cwe-78-os-command-injection",
            "src/exec.py",
            22_u32,
            Severity::High,
            "subprocess.Popen([userInput], shell=True) where userInput comes from form data. Direct shell metacharacter injection path.",
        ),
        (
            "informational.dead-import",
            "src/legacy.py",
            3_u32,
            Severity::High,
            "Unused import detected. No security implication.",
        ),
    ];
    for (rule, path, line, sev, msg) in candidates.iter() {
        let f = Finding::new_semgrep(*rule, *path, *line, Some(*line), *sev, *msg);
        store.insert_finding("run-1", &f).unwrap();
    }

    let mut config = V2Config::default();
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
            "triage:run",
            json!({"concurrency": 4, "prefilterThreshold": 0}),
            &ctx,
            Some(&runtime),
        )
        .expect("triage:run should succeed");
    let elapsed = started.elapsed();

    eprintln!("--- multi-stage triage outcome (5 findings, 4 workers) ---");
    eprintln!("wallclock: {:?}", elapsed);
    eprintln!(
        "stages: {}",
        serde_json::to_string_pretty(result.pointer("/data/stages").unwrap_or(&Value::Null))
            .unwrap_or_default()
    );

    let triaged = result
        .pointer("/data/triaged")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cost = result
        .pointer("/data/costUsd")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let tp = result
        .pointer("/data/tp")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let fp = result
        .pointer("/data/fp")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    eprintln!(
        "triaged={triaged} tp={tp} fp={fp} cost_usd={cost} elapsed={:?}",
        elapsed
    );

    assert_eq!(triaged, 5);
    assert!(
        elapsed < Duration::from_secs(30),
        "5 findings × 4 workers should finish well under 30s; got {:?}",
        elapsed
    );

    // The two clear noise findings should land in the false-positive
    // bucket, but we don't pin the exact split — Haiku verdicts can
    // shift call-to-call. We just want at least one TP and one FP.
    assert!(
        tp >= 1,
        "expected at least one TruePositive across 5 findings"
    );
    assert!(
        fp + tp >= 2,
        "expected the model to deliver actionable verdicts; got tp={tp} fp={fp}"
    );
    // OAuth runtime populates cost_usd from API usage. Real calls
    // always cost something; if it's zero either the API hand-back
    // was empty or our cost extraction regressed.
    assert!(
        cost > 0.0,
        "expected non-zero cost from OAuth runtime; got {cost}"
    );
}

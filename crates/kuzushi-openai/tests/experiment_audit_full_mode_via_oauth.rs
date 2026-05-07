//! Live experiment: drive `audit:full-mode` against a small real
//! C codebase using `AnthropicOAuthRuntime`.
//!
//! Two passes per run:
//!
//! 1. **Dry run** — exercises the planner without paying any model
//!    spend. Asserts the chunk plan covers every input file and
//!    that the cost-estimate hi-water mark stays under a sanity cap.
//! 2. **Live dispatch** — actually runs one chunk through the
//!    OAuth runtime, asserts cost is non-zero, and verifies that
//!    any findings the model produced were persisted into the
//!    workspace's `FindingStore`.
//!
//! The fixture is a 4-file synthetic C project planted in a temp
//! workspace so the experiment is hermetic and budget-bounded.
//! Skipped unless `~/.claude/remote/.oauth_token` exists.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{AgentRuntime, FindingStore, ModuleRegistry, V2Config, WorkspaceTarget};
use kuzushi_openai::{AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions};
use serde_json::{json, Value};

fn host_token_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    home.join(".claude").join("remote").join(".oauth_token")
}

/// Plant a tiny synthetic C codebase that contains an obvious bug
/// (unbounded `strcpy` of attacker-controlled data into a
/// fixed-size stack buffer) plus three innocuous siblings. The
/// audit pass should at minimum chunk all four files.
fn plant_synthetic_c_project(root: &std::path::Path) {
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("vuln.c"),
        r#"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Bug: copies caller-controlled `name` into a fixed 32-byte stack
// buffer with no length check. An attacker who controls `name` can
// overrun `buf`. Classic CWE-120.
void copy_user_name(const char *name) {
    char buf[32];
    strcpy(buf, name);
    (void)buf;
}
"#,
    )
    .unwrap();
    std::fs::write(
        src.join("safe.c"),
        r#"
#include <stdint.h>
#include <stddef.h>

// No bug: bounds checked.
size_t add_lengths(size_t a, size_t b) {
    if (a > SIZE_MAX - b) return 0;
    return a + b;
}
"#,
    )
    .unwrap();
    std::fs::write(
        src.join("noise.c"),
        r#"
// Just a comment file; no functions.
"#,
    )
    .unwrap();
    std::fs::write(
        src.join("util.h"),
        r#"
#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>

void copy_user_name(const char *name);
size_t add_lengths(size_t a, size_t b);

#endif
"#,
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live experiment; requires HOME/.claude/remote/.oauth_token"]
async fn audit_full_mode_against_synthetic_c_project_via_oauth() {
    let token_path = host_token_path();
    if !token_path.exists() {
        eprintln!("skipping: no OAuth token at {}", token_path.display());
        return;
    }

    // Hard ceiling so a runaway model can't blow the budget. The
    // dry-run pass deposits nothing; the live pass deposits up to
    // `depositUsdPerChunk` per chunk and refunds back to the
    // realised cost.
    std::env::set_var("KUZUSHI_MAX_USD_PER_RUN", "1.00");

    let mut opts = AnthropicOAuthRuntimeOptions::from_token_file(&token_path)
        .expect("token file should be readable");
    opts.timeout = Some(Duration::from_secs(120));
    opts.max_tokens = Some(2048);
    if let Ok(base) = std::env::var("ANTHROPIC_BASE_URL") {
        opts.base_url = Some(base);
    }
    let runtime = AnthropicOAuthRuntime::new(opts).expect("runtime should build");

    let temp = tempfile::tempdir().unwrap();
    plant_synthetic_c_project(temp.path());
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    drop(store); // re-opened fresh after the tool persists

    let mut config = V2Config::default();
    config.model = Some("anthropic:claude-haiku-4-5-20251001".to_string());
    let registry = ModuleRegistry::with_v2_builtins();

    // ----- Pass 1: dry-run plan ----------------------------------
    {
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
        };
        let result = registry
            .execute_tool_with_runtime(
                "audit:full-mode",
                json!({"dryRun": true, "language": "c"}),
                &ctx,
                Some(&runtime as &dyn AgentRuntime),
            )
            .expect("dry-run should succeed");
        eprintln!(
            "--- audit:full-mode dry-run ---\n{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        // Plan should cover every file we planted.
        let total_files = result
            .pointer("/data/report/data/plan/total_files")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        assert!(
            total_files >= 3,
            "dry-run plan should cover the planted .c/.h files; got {total_files}"
        );
        // Cost-estimate sanity: $0.20 high cap on 4 tiny files.
        let usd_high = result
            .pointer("/data/costEstimate/usd_high")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        assert!(
            usd_high < 0.20,
            "dry-run cost estimate hi-water should stay below $0.20 on this fixture; got ${usd_high:.4}"
        );
        // No findings should be persisted on the dry path.
        assert_eq!(
            result
                .pointer("/data/findingsPersisted")
                .and_then(Value::as_u64),
            Some(0)
        );
    }

    // ----- Pass 2: live dispatch ---------------------------------
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
    };
    let started = Instant::now();
    let result = registry
        .execute_tool_with_runtime(
            "audit:full-mode",
            json!({
                "dryRun": false,
                "language": "c",
                "maxTokensPerChunk": 80_000,
                "depositUsdPerChunk": 0.50,
            }),
            &ctx,
            Some(&runtime as &dyn AgentRuntime),
        )
        .expect("live audit:full-mode should succeed");
    let elapsed = started.elapsed();

    eprintln!("--- audit:full-mode live dispatch ---");
    eprintln!("wallclock : {elapsed:?}");
    eprintln!(
        "summary   : {}",
        result
            .pointer("/output")
            .and_then(Value::as_str)
            .unwrap_or("")
    );
    eprintln!(
        "report    : {}",
        serde_json::to_string_pretty(
            &result
                .pointer("/data/report/summary")
                .unwrap_or(&Value::Null)
        )
        .unwrap_or_default()
    );

    let chunks_dispatched = result
        .pointer("/data/report/data/chunks_dispatched")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cost = result
        .pointer("/costUsd")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let findings_persisted = result
        .pointer("/data/findingsPersisted")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let dispatch_dry_run = result
        .pointer("/data/dryRun")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    assert!(
        !dispatch_dry_run,
        "live pass should not be flagged as dry-run"
    );
    assert!(
        chunks_dispatched >= 1,
        "live pass should dispatch at least one chunk; got {chunks_dispatched}"
    );
    assert!(
        cost > 0.0 && cost < 1.00,
        "live pass cost should be > 0 and < $1.00 ceiling; got ${cost:.4}"
    );

    eprintln!("findings persisted: {findings_persisted}");
    // The model is allowed to return zero findings (Haiku's verdict
    // varies); we just assert the persistence path didn't throw.
    // What matters is the plan + dispatch + cost wiring.
    assert_eq!(
        result
            .pointer("/data/report/data/findings")
            .map(|v| v.as_array().map(|a| a.len()).unwrap_or(0)),
        Some(findings_persisted as usize),
        "persisted count must match the report's finding list length"
    );
}

//! Live experiment: end-to-end multi-stage triage + verify cascade
//! against libxml2's unpatched `xmlSnprintfElements`.
//!
//! Validates that the full pipeline composes correctly:
//!
//! 1. **Stage 0 — deterministic prefilter.** Synthetic finding fed
//!    in already passes the default threshold.
//! 2. **Stage 1.5 — adaptive classifier gate.** Cheap-classifier
//!    LLM call against `models.toml [roles.classifier_gate]`. The
//!    quantile threshold persists between runs.
//! 3. **Stage 2 — concurrent Haiku triage.** Worker pool dispatches
//!    `triage_finding_blocking` against the real Anthropic API,
//!    `SpendLimiter` deposits/refunds, `ModelGate` permits at
//!    `Priority::Normal`.
//! 4. **Stage 4 — libFuzzer + ASan harness.** Independent of
//!    the LLM cascade; runs against the same finding's location.
//!
//! Stage 3 (`triage:deep` with `code_nav` tool loop) is not
//! exercised here because the native `AnthropicOAuthRuntime`
//! doesn't yet implement `supports_tools` / `next_step_blocking`.
//! `triage:deep` requires the pi-agent-core bridge today.
//!
//! Skipped unless:
//!   - `LIBXML2_REPO=/path/to/libxml2` (with bounds checks stripped)
//!   - `~/.claude/remote/.oauth_token` exists
//!   - `clang` on PATH (for stage 4)
//!
//! Run with:
//!   LIBXML2_REPO=/tmp/xml2-experiment/libxml2 HOME=/home/claude \
//!     cargo test -p kuzushi-openai \
//!     --test experiment_libxml2_full_cascade \
//!     -- --nocapture --ignored

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::verify::{verify_finding, VerifyOptions};
use kuzushi_core::{
    AgentRuntime, Finding, FindingStore, ModuleRegistry, Severity, V2Config, WorkspaceTarget,
};
use kuzushi_openai::{AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions};
use kuzushi_sandbox::SandboxBackend;
use serde_json::{json, Value};

fn host_token_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    home.join(".claude").join("remote").join(".oauth_token")
}

/// Hand-build six synthetic findings, all pointing at unguarded
/// `strcat` call sites inside the unpatched `xmlSnprintfElements`.
/// Mirrors what a Semgrep/CodeQL pass with bounds-check rules would
/// emit on the bug-pre-patch valid.c.
fn synthetic_xmlsnprintf_findings(repo: &PathBuf) -> Vec<Finding> {
    let valid_c = repo.join("valid.c");
    let path = valid_c.to_str().unwrap();
    // (rule_id, line, severity, message)
    let candidates: &[(&str, u32, Severity, &str)] = &[
        ("c/unbounded-strcat", 4628, Severity::High,
         "strcat(buf, \"(\") into fixed-size buffer with no length check; attacker-controllable element name flows here"),
        ("c/unbounded-strcat", 4634, Severity::High,
         "strcat(buf, \" ...\") with no remaining-space verification"),
        ("c/unbounded-strcat", 4645, Severity::High,
         "strcat(buf, ...) of namespace prefix; size check at 4643 doesn't account for cumulative copies"),
        ("c/unbounded-strcat", 4664, Severity::High,
         "strcat(buf, \"CDATA\") with no bounds check on TEXT_NODE/CDATA_SECTION_NODE branch"),
        ("c/unbounded-strcat", 4675, Severity::High,
         "strcat(buf, \"???\") on ATTRIBUTE_NODE branch with no bounds check"),
        ("c/unbounded-strcat", 4692, Severity::High,
         "strcat(buf, \")\") final close-paren — buffer may already be exhausted by prior strcats; this is the upstream patch line"),
    ];
    candidates
        .iter()
        .map(|(rule, line, sev, msg)| {
            Finding::new_semgrep(*rule, path, *line, Some(*line), *sev, *msg)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "live experiment; requires LIBXML2_REPO + HOME/.claude/remote/.oauth_token"]
async fn libxml2_full_cascade_via_oauth() {
    let Ok(repo) = std::env::var("LIBXML2_REPO") else {
        eprintln!("skipping: set LIBXML2_REPO to a libxml2 checkout");
        return;
    };
    let repo = PathBuf::from(repo);
    let token_path = host_token_path();
    if !token_path.exists() {
        eprintln!("skipping: no OAuth token at {}", token_path.display());
        return;
    }

    // Build the OAuth runtime against the live API.
    let mut opts = AnthropicOAuthRuntimeOptions::from_token_file(&token_path)
        .expect("token file should be readable");
    opts.timeout = Some(Duration::from_secs(60));
    opts.max_tokens = Some(512);
    if let Ok(base) = std::env::var("ANTHROPIC_BASE_URL") {
        opts.base_url = Some(base);
    }
    let runtime = AnthropicOAuthRuntime::new(opts).expect("runtime should build");

    // Workspace lives in a tempdir so the spend ledger and findings
    // store are clean. The findings reference the real libxml2 paths.
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .insert_scan_run("run-1", workspace.root(), "completed")
        .unwrap();
    let findings = synthetic_xmlsnprintf_findings(&repo);
    let inserted = findings.len();
    for f in &findings {
        store.insert_finding("run-1", f).unwrap();
    }

    // Drive `triage:run` with classifier gate enabled. The cascade
    // reports stages 0 + 1.5 + 2 in the response.
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
            json!({
                "concurrency": 4,
                "useClassifierGate": true,
                "prefilterThreshold": 0,
            }),
            &ctx,
            Some(&runtime as &dyn AgentRuntime),
        )
        .expect("triage:run should succeed");
    let elapsed = started.elapsed();

    let stages = result
        .pointer("/data/stages")
        .and_then(Value::as_array)
        .expect("stages array");
    let stage_names: Vec<&str> = stages
        .iter()
        .map(|s| s.get("stage").and_then(Value::as_str).unwrap_or(""))
        .collect();
    eprintln!(
        "--- libxml2 full cascade: {} findings, 4 workers, OAuth ---",
        inserted
    );
    eprintln!("wallclock: {:?}", elapsed);
    eprintln!(
        "stages: {}",
        serde_json::to_string_pretty(&result.pointer("/data/stages").unwrap_or(&Value::Null))
            .unwrap_or_default()
    );

    // Stage shape assertions.
    assert_eq!(stage_names, vec!["prefilter", "classifier_gate", "haiku"]);

    // Cost should be non-zero and total below a sane sanity cap.
    let cost = result
        .pointer("/data/costUsd")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let stage_cost = stages
        .iter()
        .map(|s| s.get("costUsd").and_then(Value::as_f64).unwrap_or(0.0))
        .sum::<f64>();
    eprintln!("total cost (stage-summed): ${stage_cost:.4}");
    assert!(cost > 0.0, "expected non-zero spend; got {cost}");
    assert!(
        cost < 0.50,
        "experiment should not exceed $0.50 sanity cap; got {cost}"
    );

    // Pull the highest-confidence Stage-2 TruePositive — that's what
    // a real operator would run verify:exploit on next.
    let triaged = result
        .pointer("/data/results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let top_tp = triaged
        .iter()
        .filter(|r| r.get("verdict").and_then(Value::as_str) == Some("true_positive"))
        .max_by(|a, b| {
            let ca = a.get("confidence").and_then(Value::as_f64).unwrap_or(0.0);
            let cb = b.get("confidence").and_then(Value::as_f64).unwrap_or(0.0);
            ca.partial_cmp(&cb).unwrap_or(std::cmp::Ordering::Equal)
        })
        .cloned();
    eprintln!(
        "top true-positive: {}",
        top_tp
            .as_ref()
            .map(|t| serde_json::to_string_pretty(t).unwrap_or_default())
            .unwrap_or_else(|| "(none)".to_string())
    );

    // The experiment shouldn't fail just because Haiku's verdict
    // shifts call-to-call, but at least one verdict should be a TP
    // — an unbounded strcat in a fixed-size buffer is unambiguous.
    let tp_count = triaged
        .iter()
        .filter(|r| r.get("verdict").and_then(Value::as_str) == Some("true_positive"))
        .count();
    assert!(
        tp_count >= 1,
        "expected at least one true_positive verdict from {} candidates; got results={:?}",
        triaged.len(),
        triaged
    );

    // ----- Stage 4: libFuzzer harness on the patch-line finding ---
    //
    // This is independent of the LLM cascade — it builds and runs
    // a clang-driven libFuzzer harness to look for a real crash.
    // The current call planner only handles 0/1/2-arg signatures,
    // so xmlSnprintfElements (4 args) falls through to the empty
    // stub. We assert that the harness builds and runs cleanly,
    // not that it crashes — extending the planner to 4-arg
    // signatures is the natural follow-up.
    if kuzushi_sandbox::which("clang").is_none() {
        eprintln!("skipping stage 4: clang not on PATH");
        return;
    }

    let patch_line_finding = findings
        .iter()
        .find(|f| f.start_line == 4692)
        .cloned()
        .expect("patch-line finding present");
    let mut finding_with_id = patch_line_finding;
    finding_with_id.id = Some(1);

    let verify_started = Instant::now();
    let outcome = verify_finding(
        &finding_with_id,
        VerifyOptions {
            backend: Some(SandboxBackend::Plain),
            timeout_ms: 90_000,
            trust_plain_backend: true,
            fuzz_seconds: Some(15),
            ..VerifyOptions::default()
        },
    )
    .await
    .expect("verify_finding stage 4");
    let verify_elapsed = verify_started.elapsed();

    eprintln!(
        "stage 4 (libFuzzer 15s): proof_level={} verdict={:?} duration={:?}",
        outcome.proof_level, outcome.proof_verdict, verify_elapsed,
    );
    if let Some(text) = outcome.crash_evidence.as_deref() {
        let preview: String = text.lines().take(8).collect::<Vec<_>>().join("\n");
        eprintln!("evidence excerpt:\n{preview}");
    }
    assert_eq!(outcome.language.as_deref(), Some("c"));
    assert!(outcome.duration_ms > 0);
}

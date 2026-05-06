//! Live experiment: run `AnthropicOAuthRuntime::triage_finding` against
//! a hand-built CWE-121 finding and print the verdict.
//!
//! Skipped unless `~/.claude/remote/.oauth_token` is readable AND the
//! `ANTHROPIC_BASE_URL` env var is set (or the host can reach
//! api.anthropic.com directly). Run with:
//!
//!     cargo test -p kuzushi-openai --test experiment_anthropic_oauth_triage \
//!         -- --nocapture --ignored

use kuzushi_core::{AgentRuntime, Finding, Severity, TriageRequest};
use kuzushi_openai::{AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions};
use std::path::PathBuf;
use std::time::Duration;

fn host_token_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    home.join(".claude").join("remote").join(".oauth_token")
}

#[tokio::test]
#[ignore = "live experiment; requires HOME/.claude/remote/.oauth_token readable. Run with --nocapture --ignored"]
async fn triage_finding_against_cwe121_via_oauth() {
    let token_path = host_token_path();
    if !token_path.exists() {
        eprintln!(
            "skipping: no OAuth token at {} — set HOME or place a token there to run this experiment",
            token_path.display()
        );
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

    // Hand-build a finding identical to what kuzushi's SAST scanner
    // would emit for the vulnerable fixture.
    let finding = Finding::new_tool(
        "experiment",
        "cwe-121-stack-overflow",
        "vulnerable.c",
        9,
        Some(13),
        Severity::Critical,
        "Function copy_attacker_buffer copies caller-supplied length \
         into a fixed-size 16-byte stack buffer with no bounds check. \
         An attacker who controls `len` can overwrite the saved frame \
         pointer and return address.",
    );

    let request = TriageRequest {
        model: "anthropic:claude-haiku-4-5-20251001".to_string(),
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        finding,
        prompt_template: None,
    };

    let outcome = runtime
        .triage_finding(request)
        .await
        .expect("triage call should succeed");

    eprintln!("--- OAuth-backed triage outcome ---");
    eprintln!("verdict   : {:?}", outcome.verdict);
    eprintln!("confidence: {}", outcome.confidence);
    eprintln!("rationale : {}", outcome.rationale);

    // Sanity contract — we don't assert on the exact verdict (the
    // model is allowed to call this needs_review on insufficient
    // context), but we *do* assert that:
    // - some response came back
    // - confidence is in [0,1]
    // - the rationale is non-trivial
    assert!(!outcome.rationale.trim().is_empty());
    assert!(outcome.confidence >= 0.0 && outcome.confidence <= 1.0);
}

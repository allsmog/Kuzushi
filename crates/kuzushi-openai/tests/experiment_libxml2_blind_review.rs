//! libxml2 blind-review experiment.
//!
//! Pulls the pre-patch source for a recent libxml2 CVE fix and asks the
//! OAuth-backed AgentRuntime to review the code for security bugs *with
//! no hint* about which function or line is vulnerable. Scores success
//! on whether any reported line falls within the patch's modified range.
//!
//! Target: commit `61e5f3e` (April 2026) — added bounds checks to
//! `xmlSnprintfElements` in `valid.c`. The pre-patch parent is
//! `b9da8bcc7854cfb950d7db2e35fec808eea12e46`. Two unguarded `strcat`
//! sites (lines 4625 and 4692 pre-patch) are the bug.
//!
//! Skipped unless:
//! - `~/.claude/remote/.oauth_token` is readable (set HOME if needed)
//! - `LIBXML2_VALID_C` env var points at a checked-out pre-patch
//!   `valid.c` from `b9da8bc...`
//!
//! Run with:
//!     LIBXML2_VALID_C=/tmp/xml2-experiment/libxml2/valid.c \
//!     HOME=/home/claude \
//!     cargo test -p kuzushi-openai \
//!       --test experiment_libxml2_blind_review -- --nocapture --ignored

use kuzushi_core::{AgentQueryRequest, AgentRuntime, AgentToolPolicy};
use kuzushi_openai::{AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions};
use std::path::PathBuf;
use std::time::Duration;

fn host_token_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    home.join(".claude").join("remote").join(".oauth_token")
}

const PATCH_LINES: &[(u32, u32)] = &[(4625, 4625), (4692, 4692)];
const FUNCTION_RANGE: (u32, u32) = (4622, 4695);

#[derive(Debug, serde::Deserialize)]
struct ModelFinding {
    line: u32,
    cwe: Option<String>,
    severity: Option<String>,
    explanation: String,
}

#[derive(Debug, serde::Deserialize)]
struct ModelReply {
    findings: Vec<ModelFinding>,
}

fn extract_function(source: &str, start: u32, end: u32) -> String {
    let mut out = String::new();
    for (idx, line) in source.lines().enumerate() {
        let n = (idx as u32) + 1;
        if n >= start && n <= end {
            out.push_str(&format!("{n:5}  {line}\n"));
        }
    }
    out
}

fn classify_hit(reported_line: u32) -> &'static str {
    for (lo, hi) in PATCH_LINES {
        if reported_line >= *lo && reported_line <= *hi {
            return "EXACT (Silver - patch line)";
        }
    }
    if reported_line >= FUNCTION_RANGE.0 && reported_line <= FUNCTION_RANGE.1 {
        return "FUNCTION (Bronze - same function)";
    }
    "MISS"
}

#[tokio::test]
#[ignore = "live experiment; requires LIBXML2_VALID_C env var + HOME/.claude/remote/.oauth_token"]
async fn libxml2_blind_review_for_unguarded_strcat() {
    let Ok(path) = std::env::var("LIBXML2_VALID_C") else {
        eprintln!("skipping: set LIBXML2_VALID_C to a pre-patch valid.c");
        return;
    };
    let token_path = host_token_path();
    if !token_path.exists() {
        eprintln!("skipping: no OAuth token at {}", token_path.display());
        return;
    }
    let source = std::fs::read_to_string(&path).expect("read pre-patch valid.c");

    let mut opts = AnthropicOAuthRuntimeOptions::from_token_file(&token_path).unwrap();
    opts.timeout = Some(Duration::from_secs(120));
    opts.max_tokens = Some(1500);
    if let Ok(base) = std::env::var("ANTHROPIC_BASE_URL") {
        opts.base_url = Some(base);
    }
    let runtime = AnthropicOAuthRuntime::new(opts).unwrap();

    let mut report = String::new();
    report.push_str("===== libxml2 blind-review experiment =====\n\n");
    report.push_str(
        "Target: libxml2 fix 61e5f3e (Apr 2026) - bounds checks on xmlSnprintfElements\n",
    );
    report.push_str(&format!(
        "Pre-patch buggy lines: {:?}\n",
        PATCH_LINES.iter().map(|(a, _)| a).collect::<Vec<_>>()
    ));
    report.push_str(&format!(
        "Function range: {}-{}\n\n",
        FUNCTION_RANGE.0, FUNCTION_RANGE.1
    ));

    // Pass A — tight window
    let tight = extract_function(&source, FUNCTION_RANGE.0, FUNCTION_RANGE.1);
    let tight_prompt = format!(
        "Below is C code from libxml2's valid.c with original line numbers. \
         Review it for security bugs - buffer overflows, OOB reads/writes, \
         integer overflows, format-string issues, missing bounds checks, anything. \
         Return ONLY JSON: \
         {{\"findings\":[{{\"line\":<int>,\"cwe\":\"<CWE-NNN>\",\"severity\":\"low|medium|high|critical\",\"explanation\":\"...\"}}]}}.\n\n```c\n{tight}\n```"
    );
    report.push_str("--- Pass A: tight window (function body only) ---\n");
    let resp_a = runtime
        .query(AgentQueryRequest {
            model: "anthropic:claude-haiku-4-5-20251001".to_string(),
            cwd: PathBuf::from("."),
            system_prompt: "You are a careful security code reviewer. Output only JSON."
                .to_string(),
            prompt: tight_prompt,
            tool_policy: AgentToolPolicy::default(),
        })
        .await
        .expect("tight pass should not error");
    score_and_report("Pass A (tight)", &resp_a.text, &mut report);

    // Pass B — wider window
    let wide_lo = FUNCTION_RANGE.0.saturating_sub(100);
    let wide_hi = FUNCTION_RANGE.1 + 100;
    let wide = extract_function(&source, wide_lo, wide_hi);
    let wide_prompt = format!(
        "Below is C code from libxml2's valid.c with original line numbers. \
         Review the entire snippet for security bugs. Be thorough. \
         Return ONLY JSON: \
         {{\"findings\":[{{\"line\":<int>,\"cwe\":\"<CWE-NNN>\",\"severity\":\"low|medium|high|critical\",\"explanation\":\"...\"}}]}}.\n\n```c\n{wide}\n```"
    );
    report.push_str(&format!(
        "\n--- Pass B: wide window ({}-{}) ---\n",
        wide_lo, wide_hi
    ));
    let resp_b = runtime
        .query(AgentQueryRequest {
            model: "anthropic:claude-haiku-4-5-20251001".to_string(),
            cwd: PathBuf::from("."),
            system_prompt: "You are a careful security code reviewer. Output only JSON."
                .to_string(),
            prompt: wide_prompt,
            tool_policy: AgentToolPolicy::default(),
        })
        .await
        .expect("wide pass should not error");
    score_and_report("Pass B (wide)", &resp_b.text, &mut report);

    eprintln!("{}", report);

    assert!(!resp_a.text.trim().is_empty(), "Pass A returned empty");
    assert!(!resp_b.text.trim().is_empty(), "Pass B returned empty");
}

fn score_and_report(label: &str, raw: &str, report: &mut String) {
    let stripped = strip_fences(raw);
    let parsed: serde_json::Result<ModelReply> = serde_json::from_str(&stripped);
    match parsed {
        Ok(reply) => {
            report.push_str(&format!(
                "{label}: model returned {} finding(s)\n",
                reply.findings.len()
            ));
            let mut any_hit = false;
            for f in &reply.findings {
                let outcome = classify_hit(f.line);
                if outcome != "MISS" {
                    any_hit = true;
                }
                report.push_str(&format!(
                    "  line {:5}  cwe={:<10}  sev={:<8}  outcome={}\n    {}\n",
                    f.line,
                    f.cwe.as_deref().unwrap_or("?"),
                    f.severity.as_deref().unwrap_or("?"),
                    outcome,
                    truncate(&f.explanation, 240),
                ));
            }
            if any_hit {
                report.push_str(&format!(
                    "{label}: HIT - at least one finding in target range\n"
                ));
            } else {
                report.push_str(&format!("{label}: MISS - no finding in target range\n"));
            }
        }
        Err(err) => {
            report.push_str(&format!(
                "{label}: could not parse JSON ({err}). Raw:\n{}\n",
                truncate(raw, 800)
            ));
        }
    }
}

fn strip_fences(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("```json") {
        if let Some((body, _)) = rest.rsplit_once("```") {
            return body.trim().to_string();
        }
    }
    if let Some(rest) = trimmed.strip_prefix("```") {
        if let Some((body, _)) = rest.rsplit_once("```") {
            return body.trim().to_string();
        }
    }
    trimmed.to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}...")
    }
}

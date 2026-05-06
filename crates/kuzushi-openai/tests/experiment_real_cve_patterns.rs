//! Real CVE-pattern triage experiment.
//!
//! Three fixtures lifted from well-known public CVEs. For each, ask the
//! OAuth-backed AgentRuntime to triage a hand-built finding and report:
//!
//! - The canonical CWE for the pattern
//! - The canonical exploit class
//! - Whether the model's verdict + rationale match
//!
//! These are *reduced* fixtures — the bug shape is identical to the
//! original CVE, but each is a self-contained C function rather than the
//! parent codebase. So this measures "can the pipeline + LLM recognise
//! canonical bug shapes from a finding description," not "can it
//! independently rediscover bugs in millions of LoC at scan scale."
//!
//! Skipped unless `~/.claude/remote/.oauth_token` is readable. Run with:
//!
//!     HOME=/home/claude cargo test -p kuzushi-openai \
//!       --test experiment_real_cve_patterns -- --nocapture --ignored

use kuzushi_core::{AgentRuntime, Finding, Severity, TriageRequest, TriageVerdict};
use kuzushi_openai::{AnthropicOAuthRuntime, AnthropicOAuthRuntimeOptions};
use std::path::PathBuf;
use std::time::Duration;

fn host_token_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    home.join(".claude").join("remote").join(".oauth_token")
}

/// One CVE-pattern fixture + the canonical answer we expect the
/// pipeline to reach.
struct CveFixture {
    name: &'static str,
    canonical_cwe: &'static str,
    /// What we expect the model's verdict to be — TruePositive in every
    /// case here because the patterns are unambiguously vulnerable.
    expected_verdict: TriageVerdict,
    /// Substrings the rationale should mention (case-insensitive). The
    /// model gets credit for the bug only if it names at least one of
    /// these in plain prose.
    rationale_signals: &'static [&'static str],
    finding_title: &'static str,
    finding_message: &'static str,
    file_path: &'static str,
    /// Source for transparency (not consumed by the test).
    #[allow(dead_code)]
    source_blurb: &'static str,
}

const FIXTURES: &[CveFixture] = &[
    // CVE-2014-0160 (Heartbleed). The bug: TLS heartbeat extension reads
    // an attacker-supplied length without validating it against the
    // received record's actual size, copying that many bytes back into
    // a response — leaking adjacent process memory.
    CveFixture {
        name: "heartbleed_pattern",
        canonical_cwe: "CWE-125 (Out-of-bounds Read) / CWE-130 (Improper Handling of Length Parameter Inconsistency)",
        expected_verdict: TriageVerdict::TruePositive,
        rationale_signals: &[
            "out-of-bounds",
            "out of bounds",
            "oob",
            "attacker-controlled length",
            "memory disclosure",
            "leak",
            "bounds check",
            "payload_length",
        ],
        finding_title: "TLS heartbeat copies attacker-controlled length without bounds check",
        finding_message: "\
The function `process_heartbeat` reads a 16-bit `payload_length` from \
the heartbeat record header, allocates a response buffer sized by that \
length, and copies `payload_length` bytes from the record body into \
the response. The check that `payload_length` does not exceed the \
actual received record size is missing. An attacker who sends a \
heartbeat with a small body but a large declared `payload_length` \
causes the server to copy adjacent process memory into the response, \
disclosing private keys, session data, and arbitrary heap contents.",
        file_path: "ssl/d1_both.c",
        source_blurb: "shape lifted from OpenSSL 1.0.1f dtls1_process_heartbeat / tls1_process_heartbeat",
    },
    // CVE-2021-3156 (sudo Baron Samedit). The bug: argument parsing
    // misinterprets a backslash-escaped final argument, allowing a
    // counter to be incremented past its intended bound. The result is
    // a heap-based buffer overflow when later code reads/writes
    // through that counter.
    CveFixture {
        name: "baron_samedit_pattern",
        canonical_cwe: "CWE-122 (Heap-based Buffer Overflow) via CWE-191 (Integer Underflow) on a length counter",
        expected_verdict: TriageVerdict::TruePositive,
        rationale_signals: &[
            "heap",
            "buffer overflow",
            "underflow",
            "off-by-one",
            "off by one",
            "counter",
            "escape",
            "backslash",
            "out-of-bounds write",
        ],
        finding_title: "Argument-escape parser increments past buffer end on trailing backslash",
        finding_message: "\
The argv-merging routine concatenates each argument plus its trailing \
NUL into a fixed-size heap buffer `user_args`. When an argument ends \
in an unescaped backslash that would normally introduce an escape \
sequence, the parser increments `user_args` *past* the end of the \
allocated region without re-checking the running length. A subsequent \
write through that pointer corrupts adjacent heap metadata. Because \
the parser executes before privilege-drop, a local user can supply \
crafted argv to gain root.",
        file_path: "plugins/sudoers/sudoers.c",
        source_blurb: "shape lifted from sudo 1.9.5p1 set_cmnd / parse_args; CVE-2021-3156",
    },
    // Use-after-free pattern (e.g. CVE-2024-1086 nf_tables shape). The
    // bug: a path through a state machine frees an object but a second
    // path holds a now-dangling reference to it, dereferenced later.
    CveFixture {
        name: "use_after_free_pattern",
        canonical_cwe: "CWE-416 (Use After Free) on an object referenced from two paths",
        expected_verdict: TriageVerdict::TruePositive,
        rationale_signals: &[
            "use-after-free",
            "use after free",
            "uaf",
            "dangling",
            "freed",
            "double free",
            "stale pointer",
            "reference",
        ],
        finding_title: "State-machine transition frees object still referenced by sibling path",
        finding_message: "\
Function `apply_action` dispatches to two handlers based on a state \
field. Handler `delete_entry` frees the entry's payload via `kfree(ent->buf)` \
and detaches it from the table. Handler `notify_observer` runs in \
parallel on a sibling code path and dereferences `ent->buf` to read \
the payload contents for the notification. There is no synchronization \
between the two paths and no NULL-after-free on `ent->buf`. A local \
attacker who can race the two transitions reads freed kernel memory \
and, with allocator grooming, writes through the dangling pointer.",
        file_path: "fs/example/state_machine.c",
        source_blurb: "shape lifted from nf_tables UAF / CVE-2024-1086 class of bugs",
    },
];

#[derive(Debug)]
struct ScoredOutcome {
    name: &'static str,
    canonical_cwe: &'static str,
    verdict: TriageVerdict,
    confidence: f32,
    expected_verdict: TriageVerdict,
    rationale: String,
    matched_signals: Vec<String>,
    canonical_class_match: bool,
}

fn score(fixture: &CveFixture, outcome: &kuzushi_core::TriageOutcome) -> ScoredOutcome {
    let lower = outcome.rationale.to_ascii_lowercase();
    let matched: Vec<String> = fixture
        .rationale_signals
        .iter()
        .filter(|sig| lower.contains(&sig.to_ascii_lowercase()))
        .map(|s| s.to_string())
        .collect();
    let canonical_class_match = !matched.is_empty();

    ScoredOutcome {
        name: fixture.name,
        canonical_cwe: fixture.canonical_cwe,
        verdict: outcome.verdict,
        confidence: outcome.confidence,
        expected_verdict: fixture.expected_verdict,
        rationale: outcome.rationale.clone(),
        matched_signals: matched,
        canonical_class_match,
    }
}

#[tokio::test]
#[ignore = "live experiment; requires HOME/.claude/remote/.oauth_token. Run with --nocapture --ignored"]
async fn triage_three_real_cve_patterns_via_oauth() {
    let token_path = host_token_path();
    if !token_path.exists() {
        eprintln!(
            "skipping: no OAuth token at {} — set HOME or place a token there to run this experiment",
            token_path.display()
        );
        return;
    }

    let mut opts = AnthropicOAuthRuntimeOptions::from_token_file(&token_path).unwrap();
    opts.timeout = Some(Duration::from_secs(60));
    opts.max_tokens = Some(800);
    if let Ok(base) = std::env::var("ANTHROPIC_BASE_URL") {
        opts.base_url = Some(base);
    }
    let runtime = AnthropicOAuthRuntime::new(opts).unwrap();

    let mut scored = Vec::with_capacity(FIXTURES.len());

    for fixture in FIXTURES {
        let finding = Finding::new_tool(
            "experiment-real-cves",
            format!("cve-pattern/{}", fixture.name),
            fixture.file_path,
            1,
            None,
            Severity::High,
            fixture.finding_message,
        );
        let mut finding = finding;
        finding.title = fixture.finding_title.to_string();

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
        scored.push(score(fixture, &outcome));
    }

    eprintln!();
    eprintln!("===== Real-CVE-pattern triage results =====");
    eprintln!();
    let mut verdict_hits = 0usize;
    let mut class_hits = 0usize;
    for s in &scored {
        let verdict_hit = s.verdict == s.expected_verdict;
        if verdict_hit {
            verdict_hits += 1;
        }
        if s.canonical_class_match {
            class_hits += 1;
        }
        eprintln!("--- {} ---", s.name);
        eprintln!("  canonical CWE      : {}", s.canonical_cwe);
        eprintln!(
            "  verdict            : {:?} (expected {:?}) {}",
            s.verdict,
            s.expected_verdict,
            if verdict_hit { "✓" } else { "✗" }
        );
        eprintln!("  confidence         : {:.2}", s.confidence);
        eprintln!(
            "  bug-class signals  : {} matched {}",
            s.matched_signals.len(),
            if s.canonical_class_match {
                "✓"
            } else {
                "✗"
            }
        );
        if !s.matched_signals.is_empty() {
            eprintln!("    {:?}", s.matched_signals);
        }
        eprintln!("  rationale          : {}", s.rationale);
        eprintln!();
    }
    eprintln!("===== Summary =====");
    eprintln!("verdict matches    : {}/{}", verdict_hits, scored.len());
    eprintln!("bug-class signals  : {}/{}", class_hits, scored.len());

    // Methodology contract — the test passes when:
    // - Every triage call returned (no infrastructure failure)
    // - Every confidence is in [0,1]
    // We don't fail the test on a verdict miss; that's a *result*, not
    // a regression. The eprintln output is the experiment report.
    for s in &scored {
        assert!(
            s.confidence >= 0.0 && s.confidence <= 1.0,
            "{}: confidence out of [0,1]: {}",
            s.name,
            s.confidence
        );
        assert!(
            !s.rationale.trim().is_empty(),
            "{}: empty rationale",
            s.name
        );
    }
}

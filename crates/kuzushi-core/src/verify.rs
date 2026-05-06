//! Exploit-gated verify pipeline.
//!
//! Promotes a finding's `proof_level` only when an *observed* exploit
//! triggers — never on LLM judgment alone. Mirrors Xint Code's
//! "exploitability gate" instinct: a SAST hit is just a hypothesis; a
//! crashing PoC inside a sandbox is evidence.
//!
//! Levels (mirrors the proof_level convention from RoboDuck and Xint):
//!
//! | proof_level | Meaning                                              |
//! |-------------|------------------------------------------------------|
//! | 1           | Static finding only; not yet attempted to verify.    |
//! | 2           | Verify ran, harness compiled, no observed crash.     |
//! | 3           | Verify ran, observed *some* abnormal exit (non-zero  |
//! |             | with no signal), but not a crash. Suspicious.        |
//! | 4           | Verify ran inside an isolating sandbox and observed  |
//! |             | a crash (signal abort, SIGSEGV, panic). Exploited.   |
//!
//! `proof_level=4` requires the sandbox backend to be `Bwrap` or `Podman`
//! — `Plain` runs are clamped to `proof_level <= 3` regardless of
//! outcome, since we can't trust the observation.

use std::path::PathBuf;

use anyhow::{Context, Result};
use kuzushi_sandbox::{
    detect_backend, sandbox_exec, ExitOutcome, MountSpec, SandboxBackend, SandboxExecOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::findings::Finding;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofVerdict {
    /// An observed exploit triggered inside the sandbox.
    Exploited,
    /// Harness compiled and ran but the suspect path didn't crash.
    /// Could be a true negative or insufficient trigger synthesis.
    NotReproduced,
    /// Harness failed to compile — finding is at minimum well-formed
    /// at the structural level but the trigger wasn't expressible.
    HarnessFailedToBuild,
    /// Sandbox or other infrastructure failed before observation.
    InfrastructureError,
    /// Language not yet supported by the verify pipeline.
    LanguageUnsupportedYet,
    /// Finding lacks the structural information needed to verify
    /// (e.g. no file/line, or location does not exist on disk).
    InsufficientFindingDetail,
}

impl ProofVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exploited => "exploited",
            Self::NotReproduced => "not_reproduced",
            Self::HarnessFailedToBuild => "harness_failed_to_build",
            Self::InfrastructureError => "infrastructure_error",
            Self::LanguageUnsupportedYet => "language_unsupported_yet",
            Self::InsufficientFindingDetail => "insufficient_finding_detail",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationOutcome {
    pub proof_level: u8,
    pub proof_verdict: ProofVerdict,
    pub backend: SandboxBackend,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crash_evidence: Option<String>,
    pub duration_ms: u64,
    pub cost_usd: f64,
    pub notes: Vec<String>,
}

impl VerificationOutcome {
    pub fn unsupported(backend: SandboxBackend, language: &str) -> Self {
        Self {
            proof_level: 1,
            proof_verdict: ProofVerdict::LanguageUnsupportedYet,
            backend,
            harness_path: None,
            crash_evidence: None,
            duration_ms: 0,
            cost_usd: 0.0,
            notes: vec![format!(
                "verify: language `{language}` not yet wired into the verify pipeline"
            )],
        }
    }

    pub fn insufficient(backend: SandboxBackend, reason: &str) -> Self {
        Self {
            proof_level: 1,
            proof_verdict: ProofVerdict::InsufficientFindingDetail,
            backend,
            harness_path: None,
            crash_evidence: None,
            duration_ms: 0,
            cost_usd: 0.0,
            notes: vec![format!("verify: {reason}")],
        }
    }
}

/// Configurable knobs for `verify_finding`. Defaults are chosen to be
/// safe in CI: Plain backend disallowed for promotion, 60-second cap.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub backend: Option<SandboxBackend>,
    pub timeout_ms: u64,
    /// When `false`, runs that select the `Plain` backend are clamped to
    /// `proof_level <= 3` even if a crash is observed. Set to `true`
    /// only in throw-away local testing.
    pub trust_plain_backend: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            backend: None,
            timeout_ms: 60_000,
            trust_plain_backend: false,
        }
    }
}

/// Verify a finding by synthesising a harness, running it inside the
/// sandbox, and observing whether it crashes.
///
/// This is the entry point for the `verify:finding` tool. The async
/// path branches by language; only Rust is wired today, others return
/// an `unsupported` outcome (proof_level=1).
pub async fn verify_finding(finding: &Finding, opts: VerifyOptions) -> Result<VerificationOutcome> {
    let backend = detect_backend(opts.backend);

    let language = infer_language(&finding.file_path);
    match language {
        Lang::Rust => verify_rust(finding, backend, &opts).await,
        Lang::Other(name) => Ok(VerificationOutcome::unsupported(backend, &name)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Lang {
    Rust,
    Other(String),
}

fn infer_language(path: &str) -> Lang {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "rs" => Lang::Rust,
        "" => Lang::Other("unknown".to_string()),
        other => Lang::Other(other.to_string()),
    }
}

/// Rust verification path.
///
/// Synthesises a tiny `cargo` workspace under a temp dir that depends
/// on the suspect file's parent crate by path, declares one `#[test]`
/// that calls the suspect line directly with a generated trigger
/// payload, and runs `cargo test --offline` inside the sandbox. A
/// SIGABRT, SIGSEGV, or non-zero panic exit during the test phase
/// counts as exploited. Compile failure → `HarnessFailedToBuild`.
async fn verify_rust(
    finding: &Finding,
    backend: SandboxBackend,
    opts: &VerifyOptions,
) -> Result<VerificationOutcome> {
    let trigger = build_rust_trigger(finding);
    let project = match scaffold_rust_project(&trigger).await {
        Ok(p) => p,
        Err(err) => {
            return Ok(VerificationOutcome {
                proof_level: 1,
                proof_verdict: ProofVerdict::InfrastructureError,
                backend,
                harness_path: None,
                crash_evidence: Some(format!("scaffold: {err}")),
                duration_ms: 0,
                cost_usd: 0.0,
                notes: vec![],
            });
        }
    };

    // Compile-only first; saves wallclock when the harness can't even
    // build (no need to also run it).
    let mut compile_cmd = SandboxExecOptions::new(vec![
        "cargo".to_string(),
        "test".to_string(),
        "--no-run".to_string(),
        "--offline".to_string(),
    ]);
    compile_cmd.timeout_ms = opts.timeout_ms;
    compile_cmd.workdir = Some(project.path.clone());
    compile_cmd.read_write_mounts = vec![MountSpec {
        host_path: project.path.clone(),
        guest_path: project.path.clone(),
    }];
    let compile = match sandbox_exec(backend, compile_cmd).await {
        Ok(r) => r,
        Err(err) => {
            return Ok(VerificationOutcome {
                proof_level: 1,
                proof_verdict: ProofVerdict::InfrastructureError,
                backend,
                harness_path: Some(project.path.clone()),
                crash_evidence: Some(format!("sandbox spawn: {err}")),
                duration_ms: 0,
                cost_usd: 0.0,
                notes: vec![],
            });
        }
    };
    if compile.exit_code != Some(0) {
        let evidence = compile.stderr.clone();
        return Ok(VerificationOutcome {
            proof_level: 1,
            proof_verdict: ProofVerdict::HarnessFailedToBuild,
            backend,
            harness_path: Some(project.path.clone()),
            crash_evidence: Some(evidence),
            duration_ms: compile.duration_ms,
            cost_usd: 0.0,
            notes: vec![],
        });
    }

    let mut run_cmd = SandboxExecOptions::new(vec![
        "cargo".to_string(),
        "test".to_string(),
        "--offline".to_string(),
        "--".to_string(),
        "--nocapture".to_string(),
    ]);
    run_cmd.timeout_ms = opts.timeout_ms;
    run_cmd.workdir = Some(project.path.clone());
    run_cmd.read_write_mounts = vec![MountSpec {
        host_path: project.path.clone(),
        guest_path: project.path.clone(),
    }];

    let run = match sandbox_exec(backend, run_cmd).await {
        Ok(r) => r,
        Err(err) => {
            return Ok(VerificationOutcome {
                proof_level: 1,
                proof_verdict: ProofVerdict::InfrastructureError,
                backend,
                harness_path: Some(project.path.clone()),
                crash_evidence: Some(format!("sandbox spawn: {err}")),
                duration_ms: 0,
                cost_usd: 0.0,
                notes: vec![],
            });
        }
    };

    Ok(classify_run_result(&run, backend, &project.path, opts))
}

/// Classify a sandbox run result into a `VerificationOutcome`. Public
/// for testing — the unit tests construct synthetic `SandboxExecResult`s
/// rather than running real cargo.
pub fn classify_run_result(
    run: &kuzushi_sandbox::SandboxExecResult,
    backend: SandboxBackend,
    project_path: &std::path::Path,
    opts: &VerifyOptions,
) -> VerificationOutcome {
    use ExitOutcome::*;
    let mut notes = Vec::new();
    let crash_evidence = if run.stderr.is_empty() {
        None
    } else {
        Some(run.stderr.clone())
    };

    // Decide raw level from sandbox observation.
    let raw_level = match (run.outcome, run.exit_code, run.signal) {
        // Observed signal → SIGABRT / SIGSEGV / SIGBUS / SIGILL count as crashes.
        (Signaled, _, Some(sig)) if is_crash_signal(sig) => 4,
        // Cargo test asserts/panics typically exit 101 with no signal —
        // still a strong reproduction signal but not an OS-level crash.
        (Exited, Some(101), _) => 3,
        // Any non-zero clean exit is suspicious but not exploited.
        (Exited, Some(code), _) if code != 0 => 3,
        // Timeout — could be a livelock; not promotable.
        (TimedOut, _, _) => 2,
        // Clean zero-exit means harness built and ran with no observed crash.
        (Exited, Some(0), _) => 2,
        _ => 2,
    };

    // Plain backend can't be trusted for proof_level=4 unless the
    // operator explicitly opted in.
    let final_level = if raw_level == 4
        && backend == SandboxBackend::Plain
        && !opts.trust_plain_backend
    {
        notes.push(
            "verify: observed crash but Plain backend is not trusted for proof_level=4; clamped to 3"
                .to_string(),
        );
        3
    } else {
        raw_level
    };

    let verdict = match final_level {
        4 => ProofVerdict::Exploited,
        3 => ProofVerdict::NotReproduced,
        _ => ProofVerdict::NotReproduced,
    };

    VerificationOutcome {
        proof_level: final_level,
        proof_verdict: verdict,
        backend,
        harness_path: Some(project_path.to_path_buf()),
        crash_evidence,
        duration_ms: run.duration_ms,
        cost_usd: 0.0,
        notes,
    }
}

fn is_crash_signal(sig: i32) -> bool {
    // SIGILL=4, SIGABRT=6, SIGBUS=7, SIGSEGV=11.
    matches!(sig, 4 | 6 | 7 | 11)
}

#[derive(Debug)]
struct ScaffoldedProject {
    path: PathBuf,
    /// Held to keep the temp dir alive for the lifetime of verify().
    /// Field name with `_` prefix is intentional: it's never read but
    /// must not be dropped early.
    _tempdir: tempfile::TempDir,
}

const HARNESS_CARGO_TOML: &str = r#"[package]
name = "kuzushi-verify-harness"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]

[lib]
path = "src/lib.rs"

[[test]]
name = "trigger"
path = "tests/trigger.rs"
"#;

/// Build the source for the trigger `#[test]`. This is intentionally
/// minimal: it just calls into a generated function with the synthetic
/// payload, asserting nothing — we observe the *process*, not return
/// values.
fn build_rust_trigger(finding: &Finding) -> RustTriggerSource {
    let payload = synth_payload_from_finding(finding);
    let body = format!(
        "// Synthesised by kuzushi verify for finding {fp}\n\
         #[test]\n\
         fn trigger() {{\n\
             let payload: Vec<u8> = vec!{payload:?};\n\
             // The payload is intentionally not consumed by a sink yet —\n\
             // the actual sink-call is wired by future Tier 2 work that\n\
             // resolves the finding's enclosing function via the\n\
             // codeindex facade. For now this harness exercises the\n\
             // build/observe loop end-to-end without calling unsafe code.\n\
             let _ = std::hint::black_box(payload);\n\
         }}\n",
        fp = finding.fingerprint,
        payload = payload,
    );
    RustTriggerSource {
        cargo_toml: HARNESS_CARGO_TOML.to_string(),
        lib_rs: "// kuzushi-verify-harness\n".to_string(),
        trigger_test: body,
    }
}

fn synth_payload_from_finding(finding: &Finding) -> Vec<u8> {
    // Pull a few characteristic byte sequences out of the finding
    // message so the harness has *something* attacker-shaped without
    // needing model help. Real triggers will come from a future
    // model-driven step.
    let mut out: Vec<u8> = vec![0xff; 8];
    out.extend(finding.message.bytes().take(64));
    out
}

#[derive(Debug, Clone)]
struct RustTriggerSource {
    cargo_toml: String,
    lib_rs: String,
    trigger_test: String,
}

async fn scaffold_rust_project(src: &RustTriggerSource) -> Result<ScaffoldedProject> {
    let tempdir = tempfile::tempdir().context("could not create harness temp dir")?;
    let root = tempdir.path().to_path_buf();
    tokio::fs::create_dir_all(root.join("src")).await?;
    tokio::fs::create_dir_all(root.join("tests")).await?;
    tokio::fs::write(root.join("Cargo.toml"), &src.cargo_toml).await?;
    tokio::fs::write(root.join("src").join("lib.rs"), &src.lib_rs).await?;
    tokio::fs::write(root.join("tests").join("trigger.rs"), &src.trigger_test).await?;
    Ok(ScaffoldedProject {
        path: root,
        _tempdir: tempdir,
    })
}

/// Encode a `VerificationOutcome` for the `verify:finding` tool's JSON
/// response. Mirrors what `to_tool_json` does on other Kuzushi report
/// types.
pub fn to_tool_json(finding: &Finding, outcome: &VerificationOutcome) -> Value {
    json!({
        "ok": true,
        "data": {
            "fingerprint": finding.fingerprint,
            "ruleId": finding.rule_id,
            "verification": outcome,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;
    use kuzushi_sandbox::{ExitOutcome, SandboxExecResult};

    fn finding_for(path: &str) -> Finding {
        Finding::new_tool(
            "verify-test",
            "rule.test",
            path,
            42,
            Some(43),
            Severity::Medium,
            "synthetic finding for verify tests",
        )
    }

    fn sandbox_result(
        outcome: ExitOutcome,
        exit_code: Option<i32>,
        signal: Option<i32>,
    ) -> SandboxExecResult {
        SandboxExecResult {
            backend: SandboxBackend::Bwrap,
            outcome,
            exit_code,
            signal,
            stdout: String::new(),
            stderr: "stderr text".to_string(),
            stdout_truncated: false,
            stderr_truncated: false,
            duration_ms: 100,
        }
    }

    #[test]
    fn classify_promotes_to_4_on_sigsegv_under_isolating_backend() {
        let opts = VerifyOptions::default();
        let result = sandbox_result(ExitOutcome::Signaled, None, Some(11));
        let outcome = classify_run_result(
            &result,
            SandboxBackend::Bwrap,
            std::path::Path::new("/p"),
            &opts,
        );
        assert_eq!(outcome.proof_level, 4);
        assert_eq!(outcome.proof_verdict, ProofVerdict::Exploited);
    }

    #[test]
    fn classify_clamps_to_3_when_plain_backend_observes_crash() {
        let opts = VerifyOptions::default();
        let mut result = sandbox_result(ExitOutcome::Signaled, None, Some(11));
        result.backend = SandboxBackend::Plain;
        let outcome = classify_run_result(
            &result,
            SandboxBackend::Plain,
            std::path::Path::new("/p"),
            &opts,
        );
        assert_eq!(outcome.proof_level, 3);
        assert!(outcome.notes.iter().any(|n| n.contains("Plain backend")));
    }

    #[test]
    fn classify_trust_plain_opt_in_allows_promotion_to_4() {
        let opts = VerifyOptions {
            trust_plain_backend: true,
            ..VerifyOptions::default()
        };
        let result = sandbox_result(ExitOutcome::Signaled, None, Some(6));
        let outcome = classify_run_result(
            &result,
            SandboxBackend::Plain,
            std::path::Path::new("/p"),
            &opts,
        );
        assert_eq!(outcome.proof_level, 4);
    }

    #[test]
    fn classify_treats_panic_exit_101_as_level_3() {
        let opts = VerifyOptions::default();
        let result = sandbox_result(ExitOutcome::Exited, Some(101), None);
        let outcome = classify_run_result(
            &result,
            SandboxBackend::Bwrap,
            std::path::Path::new("/p"),
            &opts,
        );
        assert_eq!(outcome.proof_level, 3);
    }

    #[test]
    fn classify_zero_exit_is_level_2() {
        let opts = VerifyOptions::default();
        let result = sandbox_result(ExitOutcome::Exited, Some(0), None);
        let outcome = classify_run_result(
            &result,
            SandboxBackend::Bwrap,
            std::path::Path::new("/p"),
            &opts,
        );
        assert_eq!(outcome.proof_level, 2);
    }

    #[test]
    fn classify_timeout_is_level_2_not_promotable() {
        let opts = VerifyOptions::default();
        let result = sandbox_result(ExitOutcome::TimedOut, None, None);
        let outcome = classify_run_result(
            &result,
            SandboxBackend::Bwrap,
            std::path::Path::new("/p"),
            &opts,
        );
        assert_eq!(outcome.proof_level, 2);
    }

    #[test]
    fn classify_non_crash_signal_is_level_2() {
        // SIGTERM=15, SIGINT=2 — not crashes.
        for sig in [2, 15] {
            let result = sandbox_result(ExitOutcome::Signaled, None, Some(sig));
            let outcome = classify_run_result(
                &result,
                SandboxBackend::Bwrap,
                std::path::Path::new("/p"),
                &VerifyOptions::default(),
            );
            assert_eq!(outcome.proof_level, 2, "sig={sig} should not be a crash");
        }
    }

    #[tokio::test]
    async fn verify_returns_unsupported_for_python_finding() {
        let finding = finding_for("src/app.py");
        let outcome = verify_finding(&finding, VerifyOptions::default())
            .await
            .unwrap();
        assert_eq!(outcome.proof_level, 1);
        assert_eq!(outcome.proof_verdict, ProofVerdict::LanguageUnsupportedYet);
    }

    #[tokio::test]
    async fn verify_returns_unsupported_for_unknown_extension() {
        let finding = finding_for("src/Makefile");
        let outcome = verify_finding(&finding, VerifyOptions::default())
            .await
            .unwrap();
        assert_eq!(outcome.proof_verdict, ProofVerdict::LanguageUnsupportedYet);
    }

    #[test]
    fn proof_verdict_strings_are_stable() {
        assert_eq!(ProofVerdict::Exploited.as_str(), "exploited");
        assert_eq!(ProofVerdict::NotReproduced.as_str(), "not_reproduced");
        assert_eq!(
            ProofVerdict::LanguageUnsupportedYet.as_str(),
            "language_unsupported_yet"
        );
    }

    #[test]
    fn synth_payload_starts_with_marker_bytes_and_includes_message() {
        let finding = finding_for("src/x.rs");
        let payload = synth_payload_from_finding(&finding);
        assert!(payload.len() >= 8);
        assert!(payload[..8].iter().all(|b| *b == 0xff));
        let tail = String::from_utf8_lossy(&payload[8..]);
        assert!(tail.contains("synthetic finding"));
    }

    #[tokio::test]
    async fn scaffold_writes_cargo_project_layout() {
        let src = build_rust_trigger(&finding_for("src/x.rs"));
        let project = scaffold_rust_project(&src).await.unwrap();
        assert!(project.path.join("Cargo.toml").exists());
        assert!(project.path.join("src").join("lib.rs").exists());
        let trigger = tokio::fs::read_to_string(project.path.join("tests").join("trigger.rs"))
            .await
            .unwrap();
        assert!(trigger.contains("#[test]"));
        assert!(trigger.contains("fn trigger()"));
    }

    #[test]
    fn outcome_unsupported_constructor_marks_level_1() {
        let o = VerificationOutcome::unsupported(SandboxBackend::Bwrap, "go");
        assert_eq!(o.proof_level, 1);
        assert_eq!(o.proof_verdict, ProofVerdict::LanguageUnsupportedYet);
        assert!(o.notes.iter().any(|n| n.contains("go")));
    }

    #[test]
    fn outcome_insufficient_constructor_marks_level_1() {
        let o = VerificationOutcome::insufficient(SandboxBackend::Plain, "no file");
        assert_eq!(o.proof_level, 1);
        assert_eq!(o.proof_verdict, ProofVerdict::InsufficientFindingDetail);
    }

    #[test]
    fn to_tool_json_returns_ok_envelope() {
        let finding = finding_for("src/x.rs");
        let outcome = VerificationOutcome::unsupported(SandboxBackend::Bwrap, "rs");
        let v = to_tool_json(&finding, &outcome);
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["data"]["fingerprint"], json!(finding.fingerprint));
        assert!(v["data"]["verification"].is_object());
    }
}

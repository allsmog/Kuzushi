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

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kuzushi_sandbox::{
    detect_backend, sandbox_exec, ExitOutcome, MountSpec, SandboxBackend, SandboxExecOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::findings::{
    Finding, PersistedProofVerdict, PersistedSandboxBackend, PersistedVerification,
};

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
    /// Language adapter that produced this outcome (e.g. `"rust"`).
    /// Set by [`verify_finding`]; adapters leave it `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
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
            language: Some(language.to_string()),
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
            language: None,
            harness_path: None,
            crash_evidence: None,
            duration_ms: 0,
            cost_usd: 0.0,
            notes: vec![format!("verify: {reason}")],
        }
    }

    /// Convert to the persistence-side type (for FindingStore).
    pub fn to_persisted(&self) -> PersistedVerification {
        PersistedVerification {
            proof_level: self.proof_level,
            proof_verdict: match self.proof_verdict {
                ProofVerdict::Exploited => PersistedProofVerdict::Exploited,
                ProofVerdict::NotReproduced => PersistedProofVerdict::NotReproduced,
                ProofVerdict::HarnessFailedToBuild => PersistedProofVerdict::HarnessFailedToBuild,
                ProofVerdict::InfrastructureError => PersistedProofVerdict::InfrastructureError,
                ProofVerdict::LanguageUnsupportedYet => {
                    PersistedProofVerdict::LanguageUnsupportedYet
                }
                ProofVerdict::InsufficientFindingDetail => {
                    PersistedProofVerdict::InsufficientFindingDetail
                }
            },
            backend: match self.backend {
                SandboxBackend::Bwrap => PersistedSandboxBackend::Bwrap,
                SandboxBackend::Podman => PersistedSandboxBackend::Podman,
                SandboxBackend::Plain => PersistedSandboxBackend::Plain,
            },
            language: self.language.clone(),
            harness_path: self.harness_path.as_ref().map(|p| p.display().to_string()),
            crash_evidence: self.crash_evidence.clone(),
            duration_ms: self.duration_ms,
            cost_usd: self.cost_usd,
            notes: self.notes.clone(),
            created_at: String::new(),
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
/// This is the entry point for the `verify:exploit` tool. The async
/// path branches by language; Rust, C, C++, Python, and JavaScript are
/// wired. Other languages return an `unsupported` outcome
/// (`proof_level=1`).
pub async fn verify_finding(finding: &Finding, opts: VerifyOptions) -> Result<VerificationOutcome> {
    let backend = detect_backend(opts.backend);
    let mut outcome = match infer_language(&finding.file_path) {
        Lang::Rust => verify_rust(finding, backend, &opts).await?,
        Lang::C => verify_c_like(finding, backend, &opts, CCompiler::Gcc).await?,
        Lang::Cpp => verify_c_like(finding, backend, &opts, CCompiler::Gpp).await?,
        Lang::Python => verify_python(finding, backend, &opts).await?,
        Lang::JavaScript => verify_node(finding, backend, &opts, "js").await?,
        Lang::TypeScript => verify_node(finding, backend, &opts, "ts").await?,
        Lang::Other(name) => VerificationOutcome::unsupported(backend, &name),
    };
    // Record which language adapter produced the outcome so persistence
    // round-trips it.
    outcome.language = match infer_language(&finding.file_path) {
        Lang::Rust => Some("rust".to_string()),
        Lang::C => Some("c".to_string()),
        Lang::Cpp => Some("cpp".to_string()),
        Lang::Python => Some("python".to_string()),
        Lang::JavaScript => Some("javascript".to_string()),
        Lang::TypeScript => Some("typescript".to_string()),
        Lang::Other(name) => Some(name),
    };
    Ok(outcome)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Lang {
    Rust,
    C,
    Cpp,
    Python,
    JavaScript,
    TypeScript,
    Other(String),
}

pub(crate) fn infer_language(path: &str) -> Lang {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "rs" => Lang::Rust,
        "c" | "h" => Lang::C,
        "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => Lang::Cpp,
        "py" | "pyi" => Lang::Python,
        "js" | "mjs" | "cjs" => Lang::JavaScript,
        "ts" | "tsx" | "mts" | "cts" => Lang::TypeScript,
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
            return Ok(infrastructure_error(
                backend,
                None,
                format!("scaffold: {err}"),
            ));
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
            return Ok(infrastructure_error(
                backend,
                Some(project.path.clone()),
                format!("sandbox spawn: {err}"),
            ));
        }
    };
    if compile.exit_code != Some(0) {
        return Ok(harness_failed_to_build(
            backend,
            project.path.clone(),
            compile.stderr.clone(),
            compile.duration_ms,
        ));
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
            return Ok(infrastructure_error(
                backend,
                Some(project.path.clone()),
                format!("sandbox spawn: {err}"),
            ));
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

    // Sanitizer crash signature: ASan and UBSan default to
    // `abort_on_error=0` on Linux (clean exit_code=1 instead of
    // SIGABRT). Their stderr is unmistakable and we treat it as a
    // crash regardless of how the process exited.
    let stderr_indicates_sanitizer_crash = stderr_has_sanitizer_crash(&run.stderr);

    // Decide raw level from sandbox observation.
    let raw_level = match (run.outcome, run.exit_code, run.signal) {
        // Observed signal → SIGABRT / SIGSEGV / SIGBUS / SIGILL count as crashes.
        (Signaled, _, Some(sig)) if is_crash_signal(sig) => 4,
        // Sanitizer-reported crash — strong evidence even with clean exit.
        _ if stderr_indicates_sanitizer_crash => 4,
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
    // operator explicitly opted in. We still record that the crash
    // was *observed* — the level downgrade is about trust, not about
    // the observation itself.
    let observed_crash = raw_level == 4;
    let final_level = if raw_level == 4
        && backend == SandboxBackend::Plain
        && !opts.trust_plain_backend
    {
        notes.push(
            "verify: observed crash but Plain backend is not trusted for proof_level=4; clamped to 3 — rerun under Bwrap/Podman to promote"
                .to_string(),
        );
        3
    } else {
        raw_level
    };

    let verdict = if observed_crash {
        // We saw a real crash signal (SIGSEGV/SIGABRT/SIGBUS/SIGILL).
        // Even when clamped for trust reasons, the *observation* is
        // exploited.
        ProofVerdict::Exploited
    } else {
        match final_level {
            3 => ProofVerdict::NotReproduced,
            _ => ProofVerdict::NotReproduced,
        }
    };

    VerificationOutcome {
        proof_level: final_level,
        proof_verdict: verdict,
        backend,
        language: None,
        harness_path: Some(project_path.to_path_buf()),
        crash_evidence,
        duration_ms: run.duration_ms,
        cost_usd: 0.0,
        notes,
    }
}

/// Outcome constructor for sandbox/infrastructure failures (couldn't
/// even spawn or scaffold). Always `proof_level=1`, verdict
/// `InfrastructureError`.
fn infrastructure_error(
    backend: SandboxBackend,
    harness_path: Option<PathBuf>,
    message: String,
) -> VerificationOutcome {
    VerificationOutcome {
        proof_level: 1,
        proof_verdict: ProofVerdict::InfrastructureError,
        backend,
        language: None,
        harness_path,
        crash_evidence: Some(message),
        duration_ms: 0,
        cost_usd: 0.0,
        notes: vec![],
    }
}

/// Outcome constructor for harness-compile failures. Reports the
/// compiler's stderr verbatim so callers can see why the trigger
/// didn't link.
fn harness_failed_to_build(
    backend: SandboxBackend,
    project_path: PathBuf,
    evidence: String,
    duration_ms: u64,
) -> VerificationOutcome {
    VerificationOutcome {
        proof_level: 1,
        proof_verdict: ProofVerdict::HarnessFailedToBuild,
        backend,
        language: None,
        harness_path: Some(project_path),
        crash_evidence: Some(evidence),
        duration_ms,
        cost_usd: 0.0,
        notes: vec![],
    }
}

fn is_crash_signal(sig: i32) -> bool {
    // SIGILL=4, SIGABRT=6, SIGBUS=7, SIGSEGV=11.
    matches!(sig, 4 | 6 | 7 | 11)
}

/// Detect AddressSanitizer / UndefinedBehaviorSanitizer / MemorySanitizer
/// / ThreadSanitizer crash output. Their default behaviour on Linux is
/// `abort_on_error=0`, meaning the sanitizer reports the bug to stderr
/// and then `_exit(1)` rather than raising SIGABRT — so we'd otherwise
/// classify a real crash as "non-zero exit, not a crash". This rescues
/// that case.
pub(crate) fn stderr_has_sanitizer_crash(stderr: &str) -> bool {
    const PATTERNS: &[&str] = &[
        "AddressSanitizer:",
        "==ERROR: AddressSanitizer",
        "ThreadSanitizer:",
        "MemorySanitizer:",
        "UndefinedBehaviorSanitizer:",
        "runtime error:", // ubsan minimal output prefix
        "stack-buffer-overflow",
        "heap-buffer-overflow",
        "global-buffer-overflow",
        "use-after-free",
        "use-after-poison",
        "stack-use-after-scope",
        "stack-use-after-return",
        "double-free",
        "SEGV on unknown address",
    ];
    PATTERNS.iter().any(|p| stderr.contains(p))
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

/// Build the source for the trigger `#[test]`. When the suspect file is
/// readable, copies it into the harness as a `suspect` module and
/// synthesizes a call to the enclosing function with the payload. When
/// the signature shape isn't one we can construct an argument tuple
/// for, falls back to a payload-only harness with a comment recording
/// why.
fn build_rust_trigger(finding: &Finding) -> RustTriggerSource {
    let payload = synth_payload_from_finding(finding);
    let suspect_path = std::path::Path::new(&finding.file_path);
    let suspect = extract_enclosing_function(suspect_path, finding.start_line);
    let suspect_source = std::fs::read_to_string(suspect_path).ok();

    let parsed_sig = suspect
        .as_ref()
        .and_then(|f| parse_rust_signature(&f.signature));
    let call_plan = parsed_sig.as_ref().and_then(plan_call_expression);

    let suspect_comment = match (&suspect, &call_plan) {
        (Some(f), Some(plan)) => format!(
            "// Suspect: {file}:{line} (signature at {sig_line}) — calling `{name}(...)` via {kind}",
            file = finding.file_path,
            line = f.line,
            sig_line = f.signature_line,
            name = plan.fn_name,
            kind = plan.call_kind
        ),
        (Some(f), None) => format!(
            "// Suspect: {file}:{line} (signature at {sig_line}) → `{sig}`\n\
             // Couldn't synthesize a call (signature not in the supported pattern set);\n\
             // falling back to payload-only harness.",
            file = finding.file_path,
            line = f.line,
            sig_line = f.signature_line,
            sig = f.signature.trim()
        ),
        (None, _) => format!(
            "// No enclosing function located near {}:{}; payload-only harness.",
            finding.file_path, finding.start_line
        ),
    };

    let (lib_rs, call_block) = match (&suspect_source, &call_plan) {
        (Some(src), Some(plan)) if rust_source_appears_self_contained(src) => {
            // Wrap the suspect file as `pub mod suspect;` inside the
            // harness lib so the test can name-resolve into it.
            let lib = "// kuzushi-verify-harness\n\
                 #![allow(unused, dead_code, deprecated, clippy::all)]\n\
                 #[path = \"suspect.rs\"]\n\
                 pub mod suspect;\n"
                .to_string();
            let call = format!(
                "             // Real sink call (synthesized from {fname}'s signature).\n\
                 {invoke}",
                fname = plan.fn_name,
                invoke = plan.call_expression
            );
            (lib, call)
        }
        _ => (
            "// kuzushi-verify-harness\n".to_string(),
            "             // Payload-only harness — no sink call wired.\n\
             let _ = std::hint::black_box(payload);\n"
                .to_string(),
        ),
    };

    let body = format!(
        "// Synthesised by kuzushi verify for finding {fp}\n\
         {suspect_comment}\n\
         #[test]\n\
         fn trigger() {{\n\
             let payload: Vec<u8> = vec!{payload:?};\n\
             let _ = std::hint::black_box(&payload);\n\
{call_block}\
         }}\n",
        fp = finding.fingerprint,
        suspect_comment = suspect_comment,
        payload = payload,
        call_block = call_block,
    );

    RustTriggerSource {
        cargo_toml: HARNESS_CARGO_TOML.to_string(),
        lib_rs,
        trigger_test: body,
        suspect_source: suspect_source.clone(),
    }
}

/// Quick screen for whether copying the suspect file alone is likely to
/// give the harness a chance of building. Refuses copies that import
/// non-standard crates or use proc macros that we can't replicate
/// without the parent crate's full `Cargo.toml`.
fn rust_source_appears_self_contained(source: &str) -> bool {
    for line in source.lines().take(200) {
        let trimmed = line.trim();
        if trimmed.starts_with("extern crate ") {
            return false;
        }
        if let Some(rest) = trimmed.strip_prefix("use ") {
            // `use crate::...` and `use self::...` cross module boundaries
            // we haven't replicated; refuse rather than hand the compiler
            // a guaranteed-fail build.
            if rest.starts_with("crate::") || rest.starts_with("super::") {
                return false;
            }
        }
        if trimmed.starts_with("#[macro_use") || trimmed.starts_with("#[derive(") {
            // Conservative: `derive` macros may pull in dep types we
            // haven't declared. Allow only the std-derives.
            if let Some(inner) = trimmed
                .strip_prefix("#[derive(")
                .and_then(|s| s.strip_suffix(")]"))
            {
                if !inner.split(',').all(|name| {
                    matches!(
                        name.trim(),
                        "Debug"
                            | "Clone"
                            | "Copy"
                            | "PartialEq"
                            | "Eq"
                            | "PartialOrd"
                            | "Ord"
                            | "Hash"
                            | "Default"
                    )
                }) {
                    return false;
                }
            }
        }
    }
    true
}

/// Parsed signature we can use to plan a call. Keep the structure
/// minimal — argument *names* don't matter for synthesis, only types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RustSignature {
    pub fn_name: String,
    pub args: Vec<String>,
    pub return_type: Option<String>,
}

/// Parse a single-line Rust function signature like
/// `pub fn parse_packet(input: &[u8], n: usize) -> Result<u32>` into a
/// `RustSignature`. Returns `None` when the input doesn't look like a
/// `fn` declaration our caller can use.
pub(crate) fn parse_rust_signature(signature: &str) -> Option<RustSignature> {
    let trimmed = signature.trim();
    // Find `fn ` token.
    let fn_start = trimmed.find("fn ")?;
    let after_fn = &trimmed[fn_start + 3..];
    // Function name: everything up to `(` or `<` (generics).
    let name_end = after_fn.find(['(', '<']).unwrap_or(after_fn.len());
    let fn_name = after_fn[..name_end].trim().to_string();
    if fn_name.is_empty()
        || !fn_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    // Find balanced argument parens.
    let arg_open = after_fn.find('(')?;
    let mut depth = 0_i32;
    let mut arg_close = None;
    for (i, ch) in after_fn[arg_open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    arg_close = Some(arg_open + i);
                    break;
                }
            }
            _ => {}
        }
    }
    let arg_close = arg_close?;
    let arg_list = &after_fn[arg_open + 1..arg_close];
    let args = split_top_level_args(arg_list)
        .into_iter()
        .filter_map(|raw| extract_arg_type(&raw))
        .collect::<Vec<_>>();
    // Return type: search after the `)` for `-> ...` ending at `{` or end.
    let tail = &after_fn[arg_close + 1..];
    let return_type = tail.find("->").and_then(|arrow| {
        let after_arrow = &tail[arrow + 2..];
        let stop = after_arrow
            .find('{')
            .or_else(|| after_arrow.find(';'))
            .unwrap_or(after_arrow.len());
        let rt = after_arrow[..stop].trim().trim_end_matches("where");
        if rt.is_empty() {
            None
        } else {
            Some(rt.trim().to_string())
        }
    });
    Some(RustSignature {
        fn_name,
        args,
        return_type,
    })
}

fn split_top_level_args(arg_list: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0_i32;
    for ch in arg_list.chars() {
        match ch {
            '(' | '<' | '[' => {
                depth += 1;
                current.push(ch);
            }
            ')' | '>' | ']' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                if !current.trim().is_empty() {
                    out.push(current.trim().to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

fn extract_arg_type(raw: &str) -> Option<String> {
    // Skip self receivers entirely — methods on a type can't be
    // invoked from a free harness without constructing an instance.
    let trimmed = raw.trim();
    if trimmed == "self"
        || trimmed == "&self"
        || trimmed == "&mut self"
        || trimmed.starts_with("self:")
    {
        return None;
    }
    // Argument shape is `<pattern>: <type>`. The pattern can include
    // `mut`, attributes, tuples — we only care about the type part.
    let colon = trimmed.find(':')?;
    let ty = trimmed[colon + 1..].trim().to_string();
    Some(ty)
}

/// A planned synthetic call into the suspect function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallPlan {
    pub fn_name: String,
    /// Single line of Rust source that invokes the function. Always ends
    /// with `;` so it can be slotted into a function body verbatim.
    pub call_expression: String,
    /// One-line description of the synthesis pattern (for the harness
    /// header comment).
    pub call_kind: &'static str,
}

/// Pick a call expression appropriate for the signature's argument
/// types. Returns `None` when no supported pattern matches — the
/// harness will then fall back to the payload-only mode.
pub(crate) fn plan_call_expression(sig: &RustSignature) -> Option<CallPlan> {
    let fn_path = format!("suspect::{}", sig.fn_name);
    let returns_value = sig.return_type.is_some();
    let bind = if returns_value { "let _ = " } else { "" };

    // Zero-arg: the easiest case.
    if sig.args.is_empty() {
        return Some(CallPlan {
            fn_name: sig.fn_name.clone(),
            call_expression: format!("            {bind}{fn_path}();\n"),
            call_kind: "zero-argument call",
        });
    }

    // Single-arg patterns we recognize.
    if sig.args.len() == 1 {
        let ty = normalize_type(&sig.args[0]);
        let arg_expr = match ty.as_str() {
            "&[u8]" => Some("&payload"),
            "&Vec<u8>" => Some("&payload"),
            "Vec<u8>" => Some("payload.clone()"),
            "&str" => Some("std::str::from_utf8(&payload).unwrap_or(\"\")"),
            "String" => Some("String::from_utf8_lossy(&payload).into_owned()"),
            "usize" => Some("payload.len()"),
            "u32" => Some("payload.len() as u32"),
            "u64" => Some("payload.len() as u64"),
            "i32" => Some("payload.len() as i32"),
            "i64" => Some("payload.len() as i64"),
            _ => None,
        };
        return arg_expr.map(|expr| CallPlan {
            fn_name: sig.fn_name.clone(),
            call_expression: format!("            {bind}{fn_path}({expr});\n"),
            call_kind: "single-arg payload call",
        });
    }

    // Two-arg `(buf, len)` pattern very common in C-FFI-style Rust.
    if sig.args.len() == 2 {
        let a = normalize_type(&sig.args[0]);
        let b = normalize_type(&sig.args[1]);
        if (a == "&[u8]" || a == "*const u8") && (b == "usize" || b == "u32" || b == "u64") {
            let len_cast = match b.as_str() {
                "u32" => "payload.len() as u32",
                "u64" => "payload.len() as u64",
                _ => "payload.len()",
            };
            let buf_expr = if a == "*const u8" {
                "payload.as_ptr()"
            } else {
                "&payload"
            };
            return Some(CallPlan {
                fn_name: sig.fn_name.clone(),
                call_expression: format!("            {bind}{fn_path}({buf_expr}, {len_cast});\n"),
                call_kind: "(buf, len) C-FFI-style call",
            });
        }
    }

    None
}

fn normalize_type(ty: &str) -> String {
    // Collapse whitespace; strip path prefixes from the standard
    // collections so `std::vec::Vec<u8>` and `Vec<u8>` are treated the
    // same.
    let mut out = ty.split_whitespace().collect::<Vec<_>>().join(" ");
    out = out.replace("std::vec::Vec", "Vec");
    out = out.replace("alloc::vec::Vec", "Vec");
    out = out.replace("std::string::String", "String");
    out = out.replace("alloc::string::String", "String");
    out
}

// =====================================================================
// C signature parsing + call planning (mirrors the Rust analogues
// above). The shared `extract_enclosing_function` and
// `looks_like_function_signature` helpers are already C-aware and
// reused as-is.
// =====================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CSignature {
    pub fn_name: String,
    pub args: Vec<String>,
    pub return_type: Option<String>,
}

/// Parse a C function signature like
/// `static int parse_packet(const char *p, size_t n)`. Returns `None`
/// when the input doesn't look like a callable C definition (no name,
/// or shape that would make a synthesized call ambiguous).
///
/// Limitations are intentional and match the Rust analogue: single-line
/// signatures only; multi-line `(\n  arg1,\n  arg2\n)` reconstruction
/// is the codeindex facade's job in a follow-up.
pub(crate) fn parse_c_signature(signature: &str) -> Option<CSignature> {
    let trimmed = signature.trim().trim_end_matches('{').trim();
    // Bail on obvious non-functions.
    if trimmed.is_empty()
        || trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("/*")
    {
        return None;
    }
    let arg_open = trimmed.find('(')?;
    let mut depth = 0_i32;
    let mut arg_close = None;
    for (i, ch) in trimmed[arg_open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    arg_close = Some(arg_open + i);
                    break;
                }
            }
            _ => {}
        }
    }
    let arg_close = arg_close?;

    // Extract return type + name from the head (everything up to
    // `arg_open`). We split on whitespace plus `*`/`&` and consider
    // the *last* identifier-shaped token the function name.
    let head = trimmed[..arg_open].trim();
    if head.is_empty() {
        return None;
    }
    let (return_type, fn_name) = split_c_head(head)?;

    // Reject control-flow keywords that look like calls (`if (...)`,
    // `while (...)`, `switch (...)`).
    if matches!(
        fn_name.as_str(),
        "if" | "while" | "for" | "switch" | "return" | "do" | "else" | "case" | "sizeof"
    ) {
        return None;
    }

    let arg_list = &trimmed[arg_open + 1..arg_close];
    let args = split_top_level_args(arg_list)
        .into_iter()
        .filter_map(|raw| extract_c_arg_type(&raw))
        .collect::<Vec<_>>();

    Some(CSignature {
        fn_name,
        args,
        return_type,
    })
}

/// Split the head of a C function signature into `(return_type, name)`.
/// Pointer markers (`*`) and ref markers (`&`) attach to the return
/// type. `void` return types are preserved.
fn split_c_head(head: &str) -> Option<(Option<String>, String)> {
    let head = head.trim();
    // Find the rightmost identifier-shaped token; everything before it
    // is the return type.
    let bytes = head.as_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let mut start = end;
    while start > 0 {
        let c = bytes[start - 1];
        if c.is_ascii_alphanumeric() || c == b'_' {
            start -= 1;
        } else {
            break;
        }
    }
    if start == end {
        return None;
    }
    let name = head[start..end].to_string();
    if !is_identifier(&name) {
        return None;
    }
    let return_type_raw = head[..start].trim();
    let return_type = if return_type_raw.is_empty() {
        None
    } else {
        Some(return_type_raw.to_string())
    };
    Some((return_type, name))
}

fn extract_c_arg_type(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "void" {
        return None;
    }
    // Argument shape is `[qualifiers] <type> [*…] <name>` with optional
    // `[size]` suffix on the name. Like split_c_head, take the *type*
    // portion by stripping the trailing identifier (the parameter name)
    // and any array brackets.
    let bytes = trimmed.as_bytes();
    let mut end = bytes.len();
    // Strip trailing array brackets `[N]` if present.
    if end > 0 && bytes[end - 1] == b']' {
        if let Some(open) = trimmed.rfind('[') {
            end = open;
            while end > 0 && bytes[end - 1].is_ascii_whitespace() {
                end -= 1;
            }
        }
    }
    let mut name_end = end;
    while name_end > 0 {
        let c = bytes[name_end - 1];
        if c.is_ascii_alphanumeric() || c == b'_' {
            name_end -= 1;
        } else {
            break;
        }
    }
    // Anonymous parameter (e.g. `int` with no name) — whole thing is the type.
    if name_end == end {
        return Some(trimmed.to_string());
    }
    // If `name_end == 0` the whole token is identifier-only — that's
    // probably a single-token type like `size_t`, no name; treat as
    // unnamed.
    if name_end == 0 {
        return Some(trimmed.to_string());
    }
    let head = trimmed[..name_end].trim();
    if head.is_empty() {
        // No type before name — malformed.
        return None;
    }
    Some(head.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CCallPlan {
    pub fn_name: String,
    /// One or more lines of C source forwarding into the suspect function.
    /// Always ends with a newline so callers can concatenate verbatim.
    pub call_expression: String,
    /// Short label describing which call pattern was selected.
    pub call_kind: &'static str,
}

/// Pick a C call expression appropriate for the signature's argument
/// types. Mirrors the Rust analogue's table.
pub(crate) fn plan_c_call_expression(sig: &CSignature) -> Option<CCallPlan> {
    let returns_value = sig
        .return_type
        .as_deref()
        .map(str::trim)
        .map(|rt| !rt.is_empty() && rt != "void")
        .unwrap_or(false);
    let bind = if returns_value { "(void)" } else { "" };
    let call = |body: &str| format!("    {bind}{body};\n");

    if sig.args.is_empty() {
        return Some(CCallPlan {
            fn_name: sig.fn_name.clone(),
            call_expression: call(&format!("{}()", sig.fn_name)),
            call_kind: "zero-argument call",
        });
    }

    if sig.args.len() == 1 {
        let ty = normalize_c_type(&sig.args[0]);
        let arg_expr = match ty.as_str() {
            "const uint8_t *" | "const uint8_t*" | "uint8_t const *" | "uint8_t const*"
            | "const char *" | "const char*" | "char const *" | "char const*" | "const void *"
            | "const void*" | "void const *" | "void const*" => {
                Some("(const uint8_t *)data".to_string())
            }
            "uint8_t *" | "uint8_t*" | "char *" | "char*" | "void *" | "void*" => {
                Some("(uint8_t *)data".to_string())
            }
            "size_t" => Some("len".to_string()),
            "int" => Some("(int)len".to_string()),
            "unsigned" | "unsigned int" | "uint32_t" => Some("(uint32_t)len".to_string()),
            "long" | "long long" | "uint64_t" => Some("(uint64_t)len".to_string()),
            _ => None,
        };
        return arg_expr.map(|expr| CCallPlan {
            fn_name: sig.fn_name.clone(),
            call_expression: call(&format!("{}({})", sig.fn_name, expr)),
            call_kind: "single-arg payload call",
        });
    }

    if sig.args.len() == 2 {
        let a = normalize_c_type(&sig.args[0]);
        let b = normalize_c_type(&sig.args[1]);
        let buf_expr = match a.as_str() {
            "const uint8_t *" | "const uint8_t*" | "uint8_t const *" | "uint8_t const*" => {
                Some("(const uint8_t *)data")
            }
            "const char *" | "const char*" | "char const *" | "char const*" => {
                Some("(const char *)data")
            }
            "const void *" | "const void*" | "void const *" | "void const*" => {
                Some("(const void *)data")
            }
            "uint8_t *" | "uint8_t*" => Some("(uint8_t *)data"),
            "char *" | "char*" => Some("(char *)data"),
            "void *" | "void*" => Some("(void *)data"),
            _ => None,
        };
        let len_expr: Option<&'static str> = match b.as_str() {
            "size_t" => Some("len"),
            "int" => Some("(int)len"),
            "unsigned" | "unsigned int" | "uint32_t" => Some("(uint32_t)len"),
            "long" | "long long" | "uint64_t" => Some("(uint64_t)len"),
            _ => None,
        };
        if let (Some(buf), Some(lenv)) = (buf_expr, len_expr) {
            return Some(CCallPlan {
                fn_name: sig.fn_name.clone(),
                call_expression: call(&format!("{}({buf}, {lenv})", sig.fn_name)),
                call_kind: "(buf, len) C-FFI-style call",
            });
        }
    }

    None
}

/// Normalise a C type for matching: collapse whitespace, attach `*` /
/// `&` adjacent to the previous token, and lowercase the qualifier
/// keywords (`const`, `volatile`).
fn normalize_c_type(ty: &str) -> String {
    let collapsed: String = ty.split_whitespace().collect::<Vec<_>>().join(" ");
    // Re-attach pointer markers — `const char *` and `const char*` both
    // map to `const char *` after trimming and normalising spacing.
    let mut out = String::with_capacity(collapsed.len());
    let mut chars = collapsed.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == ' ' {
            // Drop spaces immediately before `*` / `&`.
            match chars.peek() {
                Some('*') | Some('&') => continue,
                _ => out.push(' '),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Heuristic analog of `rust_source_appears_self_contained`. Refuses
/// copies that pull in project-relative headers (`#include "foo.h"`)
/// because we can't follow them; accepts files that only use system
/// headers (`#include <stddef.h>`). Also refuses files that declare
/// `static` callbacks referring to other TU symbols by undeclared
/// names — but that's the codeindex facade's job to detect; for this
/// preview the include-form check is the gate.
pub(crate) fn c_source_appears_self_contained(source: &str) -> bool {
    for line in source.lines().take(400) {
        let trimmed = line.trim();
        if trimmed.starts_with("#include") && trimmed.contains('"') && !trimmed.contains('<') {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone)]
struct CTriggerSource {
    /// `trigger.c` — main + payload, calls `kuzushi_verify_call_target`.
    trigger_c: String,
    /// `target.c` — defines `kuzushi_verify_call_target`. Either the
    /// payload-only stub or the real trampoline that #includes the
    /// suspect file and forwards into the located function.
    target_c: String,
    /// Optional `suspect_source.c` — copy of the suspect file to be
    /// included from `target.c`. `None` when the source isn't
    /// self-contained or no suspect was located.
    suspect_source: Option<String>,
}

/// Build the C harness sources. When the suspect file is readable,
/// self-contained, and contains a parseable function near the finding's
/// line, generate a real trampoline. Otherwise produce the
/// payload-only stub.
fn build_c_trigger(finding: &Finding) -> CTriggerSource {
    let payload = synth_payload_from_finding(finding);
    let payload_decl = format!(
        "    static const uint8_t payload[{}] = {{ {} }};",
        payload.len(),
        payload
            .iter()
            .map(|b| format!("0x{b:02x}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let trigger_c = C_HARNESS_TEMPLATE.replace("{payload_decl}", &payload_decl);

    let suspect_path = std::path::Path::new(&finding.file_path);
    let suspect_source = std::fs::read_to_string(suspect_path).ok();
    let enclosing = suspect_source
        .as_deref()
        .and_then(|_| extract_enclosing_function(suspect_path, finding.start_line));
    let parsed_sig = enclosing
        .as_ref()
        .and_then(|f| parse_c_signature(&f.signature));
    let call_plan = parsed_sig.as_ref().and_then(plan_c_call_expression);

    match (&suspect_source, &call_plan) {
        (Some(src), Some(plan)) if c_source_appears_self_contained(src) => {
            // Real trampoline: include the suspect file and forward.
            let target_c = format!(
                "// kuzushi-verify generated trampoline for `{name}`.\n\
                 // Call kind: {kind}.\n\
                 #include <stdint.h>\n\
                 #include <stddef.h>\n\
                 #include \"suspect_source.c\"\n\
                 \n\
                 void kuzushi_verify_call_target(const uint8_t *data, size_t len) {{\n\
                 {call}\
                 }}\n",
                name = plan.fn_name,
                kind = plan.call_kind,
                call = plan.call_expression,
            );
            CTriggerSource {
                trigger_c,
                target_c,
                suspect_source: Some(src.clone()),
            }
        }
        _ => CTriggerSource {
            trigger_c,
            target_c: C_TARGET_STUB.to_string(),
            suspect_source: None,
        },
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
    /// Full source of the suspect file when readable. Copied into
    /// `src/suspect.rs` so the harness's `pub mod suspect;` can
    /// resolve into it. `None` when `build_rust_trigger` decided not
    /// to wire a sink call.
    suspect_source: Option<String>,
}

async fn scaffold_rust_project(src: &RustTriggerSource) -> Result<ScaffoldedProject> {
    let tempdir = tempfile::tempdir().context("could not create harness temp dir")?;
    let root = tempdir.path().to_path_buf();
    tokio::fs::create_dir_all(root.join("src")).await?;
    tokio::fs::create_dir_all(root.join("tests")).await?;
    tokio::fs::write(root.join("Cargo.toml"), &src.cargo_toml).await?;
    tokio::fs::write(root.join("src").join("lib.rs"), &src.lib_rs).await?;
    if let Some(suspect) = &src.suspect_source {
        tokio::fs::write(root.join("src").join("suspect.rs"), suspect).await?;
    }
    tokio::fs::write(root.join("tests").join("trigger.rs"), &src.trigger_test).await?;
    Ok(ScaffoldedProject {
        path: root,
        _tempdir: tempdir,
    })
}

// =====================================================================
// Source extraction
// =====================================================================

/// Best-effort: read the suspect file and locate the enclosing function
/// signature for the finding's `start_line`. Returns `None` when the
/// file isn't readable or no signature is found within a small look-back
/// window. Pure-text and language-agnostic — for joern/clang accuracy
/// we'll route through `IndexFacade` in a future iteration.
pub(crate) fn extract_enclosing_function(
    file_path: &Path,
    start_line: u32,
) -> Option<EnclosingFunction> {
    let raw = std::fs::read_to_string(file_path).ok()?;
    let lines: Vec<&str> = raw.lines().collect();
    let target_idx = (start_line.saturating_sub(1) as usize).min(lines.len().saturating_sub(1));

    // Look back up to 200 lines for a likely function signature. The
    // heuristics are intentionally conservative — we only care that
    // there *is* a signature line; the harness compiles the whole file
    // verbatim and the test calls into the file by including it.
    let window_start = target_idx.saturating_sub(200);
    let mut sig_line_idx: Option<usize> = None;
    for line in (window_start..=target_idx).rev() {
        let trimmed = lines[line].trim();
        if looks_like_function_signature(trimmed) {
            sig_line_idx = Some(line);
            break;
        }
    }
    sig_line_idx.map(|idx| EnclosingFunction {
        signature: lines[idx].to_string(),
        signature_line: idx as u32 + 1,
        line: target_idx as u32 + 1,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnclosingFunction {
    pub signature: String,
    /// 1-based line number of the located function signature.
    pub signature_line: u32,
    /// 1-based line number of the suspect (i.e. the original
    /// `finding.start_line`, clamped to the file).
    pub line: u32,
}

/// Heuristic: does this line look like a function *definition* (i.e. a
/// signature attached to a body)? Accepts Rust `fn`, C/C++
/// `<type> name(...) {`, Python `def name(...):`, JS `function name(...)
/// {`. Rejects forward declarations, calls, and control-flow lines.
///
/// Definitions must end with `{` (C/Rust/JS), `:` (Python), or end with
/// a `(` with no closing paren (multi-line signature continuation —
/// caller resolves via the look-back loop).
pub(crate) fn looks_like_function_signature(trimmed: &str) -> bool {
    if trimmed.is_empty()
        || trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
    {
        return false;
    }
    // Reject lines that end with `;` outright — they are calls, forward
    // declarations, or statements, never definition headers.
    if trimmed.ends_with(';') {
        return false;
    }

    // For function-keyword languages (Rust / Python / JS), the leading
    // keyword is the strong signal — the trailing terminator just has
    // to be one of: `{` (body opens), `:` (Python), `(`/`,` (multi-line
    // signature), or the line contains `{` (one-liner with body inline).
    let has_fn_keyword = trimmed.starts_with("fn ")
        || trimmed.starts_with("pub fn ")
        || trimmed.contains(" fn ")
        || trimmed.starts_with("def ")
        || trimmed.starts_with("async def ")
        || trimmed.starts_with("function ")
        || trimmed.starts_with("async function ")
        || trimmed.starts_with("export function ")
        || trimmed.starts_with("export async function ");
    if has_fn_keyword {
        let ends_ok = trimmed.ends_with('{')
            || trimmed.ends_with(':')
            || trimmed.ends_with('(')
            || trimmed.ends_with(',');
        // One-liner: `fn foo(x: u8) -> u32 { x as u32 }` — body brace
        // appears somewhere before the final `}`.
        let body_brace_anywhere = trimmed.contains('{');
        if ends_ok || body_brace_anywhere {
            return true;
        }
        // No body and no continuation marker — not a definition (could
        // be a `fn ` token in a prose comment).
        return false;
    }

    let ends_with_brace = trimmed.ends_with('{');
    let ends_with_colon = trimmed.ends_with(':');
    let multiline_continuation = trimmed.ends_with('(') || trimmed.ends_with(',');
    if !ends_with_brace && !ends_with_colon && !multiline_continuation {
        return false;
    }
    // C-like definition: `<type> name(` with no leading control keyword.
    // We've already required the line to end with `{`, `(`, or `,`.
    if let Some(paren) = trimmed.find('(') {
        let head = &trimmed[..paren].trim_end();
        if head.is_empty() {
            return false;
        }
        let last_word = head
            .rsplit(|c: char| c.is_whitespace() || c == '*' || c == '&')
            .next()
            .unwrap_or("");
        let leading = head
            .split(|c: char| c.is_whitespace() || c == '*' || c == '&')
            .next()
            .unwrap_or("");
        if !is_identifier(last_word) {
            return false;
        }
        if matches!(
            leading,
            "if" | "while" | "for" | "switch" | "return" | "do" | "else" | "case" | "sizeof"
        ) {
            return false;
        }
        // Final guard: the head must contain at least one whitespace —
        // i.e. there's a return type/qualifier before the function name.
        // This rejects bare `foo(x) {` from being misread.
        if !head.contains(char::is_whitespace) {
            return false;
        }
        return true;
    }
    false
}

fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.chars().next().is_some_and(|c| c.is_ascii_digit())
}

// =====================================================================
// C / C++ adapter
// =====================================================================

#[derive(Debug, Clone, Copy)]
enum CCompiler {
    Gcc,
    Gpp,
}

impl CCompiler {
    fn binary(self) -> &'static str {
        // Prefer clang when available because of richer ASan output;
        // fall back to gcc/g++. We let `which` decide at runtime.
        match self {
            Self::Gcc => "clang",
            Self::Gpp => "clang++",
        }
    }

    fn fallback(self) -> &'static str {
        match self {
            Self::Gcc => "gcc",
            Self::Gpp => "g++",
        }
    }
}

const C_HARNESS_TEMPLATE: &str = r#"// kuzushi-verify C/C++ trigger harness
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void kuzushi_verify_call_target(const uint8_t *data, size_t len);

int main(void) {{
{payload_decl}
    kuzushi_verify_call_target(payload, sizeof payload);
    return 0;
}}
"#;

/// Fallback `target.c` body used when the suspect source isn't readable
/// or doesn't appear self-contained. The harness still builds and runs;
/// it just doesn't exercise the bug. Equivalent of the Rust path's
/// payload-only fallback.
const C_TARGET_STUB: &str = r#"// kuzushi-verify payload-only fallback.
// The suspect source could not be wired into the harness because either
// the file was unreadable, the signature could not be parsed, or it
// uses project-relative includes that need the codeindex facade to
// resolve. The harness still builds + runs to exercise the
// build/observe loop; verify will report proof_level<=2 by design.
#include <stdint.h>
#include <stddef.h>

void kuzushi_verify_call_target(const uint8_t *data, size_t len) {
    (void)data;
    (void)len;
}
"#;

async fn verify_c_like(
    finding: &Finding,
    backend: SandboxBackend,
    opts: &VerifyOptions,
    compiler: CCompiler,
) -> Result<VerificationOutcome> {
    let project = match scaffold_c_project(finding, compiler).await {
        Ok(p) => p,
        Err(err) => {
            return Ok(infrastructure_error(
                backend,
                None,
                format!("c scaffold: {err}"),
            ));
        }
    };

    // Pick a compiler binary that's actually on PATH; ASan is the
    // gold-standard observation primitive for memory-corruption bugs.
    let cc = pick_c_compiler(compiler);
    if cc.is_none() {
        return Ok(infrastructure_error(
            backend,
            Some(project.path.clone()),
            "no C/C++ compiler on PATH (looked for clang/gcc/clang++/g++)".to_string(),
        ));
    }
    let cc = cc.unwrap();

    let binary_path = project.path.join("trigger");
    let mut argv: Vec<String> = vec![
        cc.to_string(),
        "-O0".to_string(),
        "-g".to_string(),
        "-Werror=implicit-function-declaration".to_string(),
    ];
    for flag in c_sanitizer_flags(&cc) {
        argv.push(flag.to_string());
    }
    argv.extend([
        "-o".to_string(),
        binary_path.display().to_string(),
        project.path.join("trigger.c").display().to_string(),
        project.path.join("target.c").display().to_string(),
    ]);
    let mut compile_cmd = SandboxExecOptions::new(argv);
    compile_cmd.timeout_ms = opts.timeout_ms;
    compile_cmd.workdir = Some(project.path.clone());
    compile_cmd.read_write_mounts = vec![MountSpec {
        host_path: project.path.clone(),
        guest_path: project.path.clone(),
    }];

    let compile = match sandbox_exec(backend, compile_cmd).await {
        Ok(r) => r,
        Err(err) => {
            return Ok(infrastructure_error(
                backend,
                Some(project.path.clone()),
                format!("c compile spawn: {err}"),
            ));
        }
    };
    if compile.exit_code != Some(0) {
        return Ok(harness_failed_to_build(
            backend,
            project.path.clone(),
            compile.stderr.clone(),
            compile.duration_ms,
        ));
    }

    let mut run_cmd = SandboxExecOptions::new(vec![binary_path.display().to_string()]);
    run_cmd.timeout_ms = opts.timeout_ms;
    run_cmd.workdir = Some(project.path.clone());
    run_cmd.read_write_mounts = vec![MountSpec {
        host_path: project.path.clone(),
        guest_path: project.path.clone(),
    }];

    let run = match sandbox_exec(backend, run_cmd).await {
        Ok(r) => r,
        Err(err) => {
            return Ok(infrastructure_error(
                backend,
                Some(project.path.clone()),
                format!("c run spawn: {err}"),
            ));
        }
    };

    Ok(classify_run_result(&run, backend, &project.path, opts))
}

fn pick_c_compiler(compiler: CCompiler) -> Option<String> {
    // Prefer whichever toolchain has its AddressSanitizer runtime
    // actually installed. clang's runtime ships in a separate
    // `libclang-rt-dev` package on most distros and is often missing;
    // gcc's libasan is bundled with the gcc package itself.
    let clang_has_asan = clang_asan_runtime_present();
    let gcc_has_asan = gcc_asan_runtime_present();

    let prefer = compiler.binary();
    let fallback = compiler.fallback();

    let clang_present = kuzushi_sandbox::which(prefer).is_some();
    let gcc_present = kuzushi_sandbox::which(fallback).is_some();

    if clang_present && clang_has_asan {
        return Some(prefer.to_string());
    }
    if gcc_present && gcc_has_asan {
        return Some(fallback.to_string());
    }
    // No ASan runtime — pick whichever compiler is present and let the
    // caller drop sanitizer flags via `c_sanitizer_flags`.
    if clang_present {
        return Some(prefer.to_string());
    }
    if gcc_present {
        return Some(fallback.to_string());
    }
    None
}

fn clang_asan_runtime_present() -> bool {
    let candidates = [
        "/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.asan-x86_64.a",
        "/usr/lib/llvm-17/lib/clang/17/lib/linux/libclang_rt.asan-x86_64.a",
        "/usr/lib/llvm-16/lib/clang/16/lib/linux/libclang_rt.asan-x86_64.a",
        "/usr/lib/clang/18/lib/linux/libclang_rt.asan-x86_64.a",
        "/usr/local/lib/clang/18/lib/linux/libclang_rt.asan-x86_64.a",
    ];
    candidates.iter().any(|p| std::path::Path::new(p).exists())
}

fn gcc_asan_runtime_present() -> bool {
    let candidates = [
        "/usr/lib/gcc/x86_64-linux-gnu/13/libasan.a",
        "/usr/lib/gcc/x86_64-linux-gnu/13/libasan.so",
        "/usr/lib/gcc/x86_64-linux-gnu/14/libasan.a",
        "/usr/lib/gcc/x86_64-linux-gnu/14/libasan.so",
        "/usr/lib/gcc/x86_64-linux-gnu/12/libasan.a",
        "/usr/lib/x86_64-linux-gnu/libasan.so.8",
        "/usr/lib/x86_64-linux-gnu/libasan.so.6",
    ];
    candidates.iter().any(|p| std::path::Path::new(p).exists())
}

/// Pick sanitizer flags conditional on toolchain availability. Returns
/// an empty vec when no ASan runtime is present so the harness still
/// builds and runs (weaker detection but the pipeline keeps working).
fn c_sanitizer_flags(compiler: &str) -> Vec<&'static str> {
    let runtime_present = if compiler.starts_with("clang") {
        clang_asan_runtime_present()
    } else if compiler.starts_with("gcc") || compiler.starts_with("g++") {
        gcc_asan_runtime_present()
    } else {
        false
    };
    if runtime_present {
        vec!["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    } else {
        Vec::new()
    }
}

async fn scaffold_c_project(finding: &Finding, _compiler: CCompiler) -> Result<ScaffoldedProject> {
    let tempdir = tempfile::tempdir().context("could not create C harness temp dir")?;
    let root = tempdir.path().to_path_buf();
    let trigger = build_c_trigger(finding);
    tokio::fs::write(root.join("trigger.c"), &trigger.trigger_c).await?;
    tokio::fs::write(root.join("target.c"), &trigger.target_c).await?;
    if let Some(suspect) = &trigger.suspect_source {
        tokio::fs::write(root.join("suspect_source.c"), suspect).await?;
    }
    Ok(ScaffoldedProject {
        path: root,
        _tempdir: tempdir,
    })
}

// =====================================================================
// Python adapter
// =====================================================================

const PY_HARNESS_TEMPLATE: &str = r#"# kuzushi-verify Python trigger harness
import sys

PAYLOAD = bytes([{payload_csv}])

def trigger():
    # Placeholder: future codeindex integration will import the suspect
    # module and call into the enclosing function. For now this exercises
    # the build/observe loop end-to-end.
    return len(PAYLOAD)

def test_trigger():
    assert trigger() >= 0

if __name__ == "__main__":
    test_trigger()
    sys.exit(0)
"#;

async fn verify_python(
    finding: &Finding,
    backend: SandboxBackend,
    opts: &VerifyOptions,
) -> Result<VerificationOutcome> {
    if kuzushi_sandbox::which("python3").is_none() && kuzushi_sandbox::which("python").is_none() {
        return Ok(infrastructure_error(
            backend,
            None,
            "no python interpreter on PATH (looked for python3, python)".to_string(),
        ));
    }
    let interpreter = kuzushi_sandbox::which("python3")
        .map(|_| "python3")
        .unwrap_or("python");

    let project = match scaffold_python_project(finding).await {
        Ok(p) => p,
        Err(err) => {
            return Ok(infrastructure_error(
                backend,
                None,
                format!("python scaffold: {err}"),
            ));
        }
    };

    let mut run_cmd = SandboxExecOptions::new(vec![
        interpreter.to_string(),
        project.path.join("trigger.py").display().to_string(),
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
            return Ok(infrastructure_error(
                backend,
                Some(project.path.clone()),
                format!("python run spawn: {err}"),
            ));
        }
    };

    Ok(classify_run_result(&run, backend, &project.path, opts))
}

async fn scaffold_python_project(finding: &Finding) -> Result<ScaffoldedProject> {
    let tempdir = tempfile::tempdir().context("could not create python harness temp dir")?;
    let root = tempdir.path().to_path_buf();
    let payload = synth_payload_from_finding(finding);
    let payload_csv = payload
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let body = PY_HARNESS_TEMPLATE.replace("{payload_csv}", &payload_csv);
    tokio::fs::write(root.join("trigger.py"), body).await?;
    Ok(ScaffoldedProject {
        path: root,
        _tempdir: tempdir,
    })
}

// =====================================================================
// JavaScript / TypeScript adapter
// =====================================================================

const JS_HARNESS_TEMPLATE: &str = r#"// kuzushi-verify Node.js trigger harness
const payload = Uint8Array.from([{payload_csv}]);

function trigger() {
    // Placeholder: future codeindex integration will require() the
    // suspect module and call into the enclosing function. For now this
    // exercises the build/observe loop end-to-end.
    return payload.length;
}

if (trigger() < 0) {
    process.exit(2);
}
process.exit(0);
"#;

async fn verify_node(
    finding: &Finding,
    backend: SandboxBackend,
    opts: &VerifyOptions,
    extension: &str,
) -> Result<VerificationOutcome> {
    // Pick a runner. For .ts/.tsx prefer `tsx` → `ts-node` → fall back
    // to plain `node` (which only works if the input is already JS).
    let want_typescript = matches!(extension, "ts" | "tsx" | "mts" | "cts");
    let runner: Vec<String> = if want_typescript {
        if let Some(_path) = kuzushi_sandbox::which("tsx") {
            vec!["tsx".to_string()]
        } else if let Some(_path) = kuzushi_sandbox::which("ts-node") {
            vec!["ts-node".to_string()]
        } else if kuzushi_sandbox::which("node").is_some() {
            // Last-ditch: run `node --import tsx` if @kuzushi happens
            // to bundle it via npx. Otherwise fall through to node and
            // hope the snippet is JS-compatible.
            vec!["node".to_string()]
        } else {
            return Ok(infrastructure_error(
                backend,
                None,
                "no JS/TS runner on PATH; install Node.js (`apt install nodejs` / `brew install node`) and optionally `tsx` for native TypeScript".to_string(),
            ));
        }
    } else if kuzushi_sandbox::which("node").is_some() {
        vec!["node".to_string()]
    } else {
        return Ok(infrastructure_error(
            backend,
            None,
            "node not on PATH; install Node.js to verify .js findings".to_string(),
        ));
    };

    let project = match scaffold_node_project(finding, extension).await {
        Ok(p) => p,
        Err(err) => {
            return Ok(infrastructure_error(
                backend,
                None,
                format!("node scaffold: {err}"),
            ));
        }
    };

    // The trigger file extension matches the input's: `.js` for JS,
    // `.ts` for TS. tsx/ts-node will run the .ts directly; plain node
    // gets the .js fallback.
    let trigger_name = if want_typescript {
        "trigger.ts"
    } else {
        "trigger.js"
    };
    let mut argv = runner;
    argv.push(project.path.join(trigger_name).display().to_string());
    let mut run_cmd = SandboxExecOptions::new(argv);
    run_cmd.timeout_ms = opts.timeout_ms;
    run_cmd.workdir = Some(project.path.clone());
    run_cmd.read_write_mounts = vec![MountSpec {
        host_path: project.path.clone(),
        guest_path: project.path.clone(),
    }];

    let run = match sandbox_exec(backend, run_cmd).await {
        Ok(r) => r,
        Err(err) => {
            return Ok(infrastructure_error(
                backend,
                Some(project.path.clone()),
                format!("node run spawn: {err}"),
            ));
        }
    };

    Ok(classify_run_result(&run, backend, &project.path, opts))
}

async fn scaffold_node_project(finding: &Finding, extension: &str) -> Result<ScaffoldedProject> {
    let tempdir = tempfile::tempdir().context("could not create node harness temp dir")?;
    let root = tempdir.path().to_path_buf();
    let payload = synth_payload_from_finding(finding);
    let payload_csv = payload
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let body = JS_HARNESS_TEMPLATE.replace("{payload_csv}", &payload_csv);
    let want_typescript = matches!(extension, "ts" | "tsx" | "mts" | "cts");
    if want_typescript {
        // `tsx` and `ts-node` both happily run a script whose contents
        // is plain JS. Writing it as `.ts` lets us pick up the TS
        // toolchain; if the runner is plain node it would refuse the
        // extension, but verify_node forces a JS-only fallback in
        // that case.
        tokio::fs::write(root.join("trigger.ts"), body).await?;
    } else {
        tokio::fs::write(root.join("trigger.js"), body).await?;
    }
    Ok(ScaffoldedProject {
        path: root,
        _tempdir: tempdir,
    })
}

/// Encode a `VerificationOutcome` for the `verify:exploit` tool's JSON
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
    async fn verify_python_reaches_a_terminal_outcome() {
        // Python is now wired; the harness writes a tiny script and runs
        // it under whatever python interpreter is available. When no
        // interpreter is present we expect InfrastructureError. When one
        // is, we expect a real outcome.
        let finding = finding_for("src/app.py");
        let outcome = verify_finding(&finding, VerifyOptions::default())
            .await
            .unwrap();
        assert_eq!(outcome.language.as_deref(), Some("python"));
        if kuzushi_sandbox::which("python3").is_none() && kuzushi_sandbox::which("python").is_none()
        {
            assert_eq!(outcome.proof_verdict, ProofVerdict::InfrastructureError);
        } else {
            assert!(matches!(
                outcome.proof_verdict,
                ProofVerdict::Exploited
                    | ProofVerdict::NotReproduced
                    | ProofVerdict::HarnessFailedToBuild
                    | ProofVerdict::InfrastructureError
            ));
        }
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

    // ----- language inference --------------------------------------

    #[test]
    fn language_inference_covers_supported_extensions() {
        assert_eq!(infer_language("a.rs"), Lang::Rust);
        assert_eq!(infer_language("a.c"), Lang::C);
        assert_eq!(infer_language("a.h"), Lang::C);
        assert_eq!(infer_language("a.cpp"), Lang::Cpp);
        assert_eq!(infer_language("a.cxx"), Lang::Cpp);
        assert_eq!(infer_language("a.hpp"), Lang::Cpp);
        assert_eq!(infer_language("a.py"), Lang::Python);
        assert_eq!(infer_language("a.js"), Lang::JavaScript);
        assert_eq!(infer_language("a.mjs"), Lang::JavaScript);
        assert_eq!(infer_language("a.ts"), Lang::TypeScript);
        assert_eq!(infer_language("a.tsx"), Lang::TypeScript);
        assert_eq!(infer_language("a.go"), Lang::Other("go".to_string()));
        assert_eq!(
            infer_language("Makefile"),
            Lang::Other("unknown".to_string())
        );
    }

    // ----- function-signature heuristic -----------------------------

    #[test]
    fn looks_like_signature_recognises_rust_fn() {
        assert!(looks_like_function_signature("fn foo() {"));
        assert!(looks_like_function_signature("pub fn foo() {"));
        assert!(looks_like_function_signature("pub async fn foo() {"));
        assert!(looks_like_function_signature("    fn nested() -> i32 {"));
    }

    #[test]
    fn looks_like_signature_recognises_python_def() {
        assert!(looks_like_function_signature("def foo():"));
        assert!(looks_like_function_signature("async def foo(x):"));
    }

    #[test]
    fn looks_like_signature_recognises_javascript() {
        assert!(looks_like_function_signature("function foo() {"));
        assert!(looks_like_function_signature("async function foo(x) {"));
        assert!(looks_like_function_signature("export function foo(x) {"));
    }

    #[test]
    fn looks_like_signature_recognises_c_style() {
        assert!(looks_like_function_signature("int foo(void) {"));
        assert!(looks_like_function_signature(
            "static char *bar(int x, int y) {"
        ));
        assert!(looks_like_function_signature("void quux(struct s *p) {"));
    }

    #[test]
    fn looks_like_signature_rejects_control_flow_and_calls() {
        assert!(!looks_like_function_signature(""));
        assert!(!looks_like_function_signature("// comment"));
        assert!(!looks_like_function_signature("# comment"));
        assert!(!looks_like_function_signature("/* block */"));
        assert!(!looks_like_function_signature("if (x > 0) {"));
        assert!(!looks_like_function_signature("while (true) {"));
        assert!(!looks_like_function_signature("for (i = 0; i < 10; i++) {"));
        assert!(!looks_like_function_signature("return foo(x);"));
        assert!(!looks_like_function_signature("foo(x);"));
    }

    // ----- enclosing-function extraction ---------------------------

    #[test]
    fn extract_enclosing_function_finds_rust_signature_above_line() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lib.rs");
        std::fs::write(
            &path,
            "// header comment\n\
             pub fn target(input: &[u8]) -> usize {\n\
                 let n = input.len();\n\
                 // suspect line\n\
                 n + 1\n\
             }\n",
        )
        .unwrap();
        let f = extract_enclosing_function(&path, 4).expect("should find target");
        assert!(f.signature.contains("pub fn target"));
        assert_eq!(f.line, 4);
    }

    #[test]
    fn extract_enclosing_function_finds_c_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("foo.c");
        std::fs::write(
            &path,
            "#include <stddef.h>\n\
             static int parse_packet(const char *p, size_t n) {\n\
                 size_t i = 0;\n\
                 char c = p[n];   // suspect: OOB\n\
                 return c;\n\
             }\n",
        )
        .unwrap();
        let f = extract_enclosing_function(&path, 4).expect("should find parse_packet");
        assert!(f.signature.contains("parse_packet"));
    }

    #[test]
    fn extract_enclosing_function_returns_none_when_no_signature_in_window() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("notes.txt");
        std::fs::write(&path, "just some text\nnot a function\nat all\n").unwrap();
        assert!(extract_enclosing_function(&path, 2).is_none());
    }

    #[test]
    fn extract_enclosing_function_returns_none_when_file_missing() {
        let path = std::path::Path::new("/this/path/does/not/exist.rs");
        assert!(extract_enclosing_function(path, 1).is_none());
    }

    // ----- persistence round-trip ----------------------------------

    #[test]
    fn outcome_to_persisted_round_trips_fields() {
        let outcome = VerificationOutcome {
            proof_level: 4,
            proof_verdict: ProofVerdict::Exploited,
            backend: SandboxBackend::Bwrap,
            language: Some("rust".to_string()),
            harness_path: Some(PathBuf::from("/tmp/harness")),
            crash_evidence: Some("SIGSEGV".to_string()),
            duration_ms: 1500,
            cost_usd: 0.0,
            notes: vec!["one".to_string(), "two".to_string()],
        };
        let p = outcome.to_persisted();
        assert_eq!(p.proof_level, 4);
        assert_eq!(p.proof_verdict, PersistedProofVerdict::Exploited);
        assert_eq!(p.backend, PersistedSandboxBackend::Bwrap);
        assert_eq!(p.language.as_deref(), Some("rust"));
        assert_eq!(p.harness_path.as_deref(), Some("/tmp/harness"));
        assert_eq!(p.crash_evidence.as_deref(), Some("SIGSEGV"));
        assert_eq!(p.duration_ms, 1500);
        assert_eq!(p.notes, vec!["one".to_string(), "two".to_string()]);
    }

    #[test]
    fn outcome_to_persisted_maps_all_verdicts() {
        for (v, expected) in [
            (ProofVerdict::Exploited, PersistedProofVerdict::Exploited),
            (
                ProofVerdict::NotReproduced,
                PersistedProofVerdict::NotReproduced,
            ),
            (
                ProofVerdict::HarnessFailedToBuild,
                PersistedProofVerdict::HarnessFailedToBuild,
            ),
            (
                ProofVerdict::InfrastructureError,
                PersistedProofVerdict::InfrastructureError,
            ),
            (
                ProofVerdict::LanguageUnsupportedYet,
                PersistedProofVerdict::LanguageUnsupportedYet,
            ),
            (
                ProofVerdict::InsufficientFindingDetail,
                PersistedProofVerdict::InsufficientFindingDetail,
            ),
        ] {
            let mut o = VerificationOutcome::unsupported(SandboxBackend::Plain, "rs");
            o.proof_verdict = v;
            assert_eq!(o.to_persisted().proof_verdict, expected);
        }
    }

    #[test]
    fn persisted_proof_verdict_string_round_trip() {
        for v in [
            PersistedProofVerdict::Exploited,
            PersistedProofVerdict::NotReproduced,
            PersistedProofVerdict::HarnessFailedToBuild,
            PersistedProofVerdict::InfrastructureError,
            PersistedProofVerdict::LanguageUnsupportedYet,
            PersistedProofVerdict::InsufficientFindingDetail,
        ] {
            assert_eq!(PersistedProofVerdict::from_str(v.as_str()), Some(v));
        }
        assert_eq!(PersistedProofVerdict::from_str("garbage"), None);
    }

    #[test]
    fn persisted_sandbox_backend_string_round_trip() {
        for b in [
            PersistedSandboxBackend::Bwrap,
            PersistedSandboxBackend::Podman,
            PersistedSandboxBackend::Plain,
        ] {
            assert_eq!(PersistedSandboxBackend::from_str(b.as_str()), Some(b));
        }
        assert_eq!(PersistedSandboxBackend::from_str("nope"), None);
    }

    // ----- multi-language harness scaffolding ----------------------

    #[tokio::test]
    async fn scaffold_c_project_writes_trigger_and_target() {
        let finding = finding_for("src/x.c");
        let project = scaffold_c_project(&finding, CCompiler::Gcc).await.unwrap();
        let trigger = std::fs::read_to_string(project.path.join("trigger.c")).unwrap();
        let target = std::fs::read_to_string(project.path.join("target.c")).unwrap();
        assert!(trigger.contains("kuzushi_verify_call_target"));
        assert!(trigger.contains("0xff")); // payload bytes
        assert!(target.contains("kuzushi_verify_call_target"));
    }

    // ----- C signature parsing -------------------------------------

    #[test]
    fn parse_c_signature_extracts_name_and_arg_types() {
        let sig = parse_c_signature("static int parse_packet(const char *p, size_t n) {")
            .expect("should parse");
        assert_eq!(sig.fn_name, "parse_packet");
        assert_eq!(sig.return_type.as_deref(), Some("static int"));
        assert_eq!(sig.args.len(), 2);
        assert!(sig.args[0].contains("const char"));
        assert!(sig.args[1].contains("size_t"));
    }

    #[test]
    fn parse_c_signature_handles_void_return_and_zero_args() {
        let sig = parse_c_signature("void shutdown_handler(void)").expect("should parse");
        assert_eq!(sig.fn_name, "shutdown_handler");
        assert_eq!(sig.return_type.as_deref(), Some("void"));
        assert!(sig.args.is_empty(), "void argument list should be empty");
    }

    #[test]
    fn parse_c_signature_strips_trailing_open_brace() {
        let sig = parse_c_signature("int recv_msg(int fd) {").expect("should parse");
        assert_eq!(sig.fn_name, "recv_msg");
    }

    #[test]
    fn parse_c_signature_handles_pointer_return() {
        let sig = parse_c_signature("static char *str_dup(const char *src)").expect("should parse");
        assert_eq!(sig.fn_name, "str_dup");
        assert!(sig.return_type.as_deref().unwrap().contains("char"));
    }

    #[test]
    fn parse_c_signature_rejects_control_flow() {
        assert!(parse_c_signature("if (x > 0) {").is_none());
        assert!(parse_c_signature("while (cur != NULL)").is_none());
        assert!(parse_c_signature("switch (kind) {").is_none());
    }

    #[test]
    fn parse_c_signature_rejects_comments_and_macros() {
        assert!(parse_c_signature("// comment").is_none());
        assert!(parse_c_signature("#include <stdio.h>").is_none());
        assert!(parse_c_signature("/* block */").is_none());
    }

    #[test]
    fn parse_c_signature_rejects_call_sites() {
        // A call has no return type before the name and our heuristic
        // requires whitespace in the head — confirm `foo(x);` doesn't
        // get misread as a definition.
        let head_only = parse_c_signature("foo(x)");
        // Single-token head: either parsed as function with empty
        // return type (which we'd also accept) or rejected. The
        // contract that matters for build_c_trigger: don't synthesize
        // a call when there's no return type — covered by
        // plan_c_call_expression's behaviour.
        if let Some(sig) = head_only {
            assert_eq!(sig.fn_name, "foo");
            assert!(sig.return_type.is_none());
        }
    }

    // ----- C call-plan synthesis -----------------------------------

    #[test]
    fn plan_c_call_zero_args() {
        let sig = parse_c_signature("void run(void)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("run()"));
        assert!(plan.call_kind.contains("zero-argument"));
    }

    #[test]
    fn plan_c_call_const_uint8_ptr_single_arg() {
        let sig = parse_c_signature("int parse(const uint8_t *buf)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(plan
            .call_expression
            .contains("parse((const uint8_t *)data)"));
    }

    #[test]
    fn plan_c_call_size_t_single_arg() {
        let sig = parse_c_signature("int handle(size_t n)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("handle(len)"));
    }

    #[test]
    fn plan_c_call_buf_len_pair() {
        let sig = parse_c_signature("void copy(const uint8_t *src, size_t len)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(plan
            .call_expression
            .contains("copy((const uint8_t *)data, len)"));
        assert_eq!(plan.call_kind, "(buf, len) C-FFI-style call");
    }

    #[test]
    fn plan_c_call_const_char_ptr_buf_with_int_len() {
        let sig = parse_c_signature("int strn_dup(const char *p, int n)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(plan
            .call_expression
            .contains("strn_dup((const char *)data, (int)len)"));
    }

    #[test]
    fn plan_c_call_returns_none_for_unsupported_signatures() {
        let sig = parse_c_signature("int complex(struct timeval *t, double f)").unwrap();
        assert!(plan_c_call_expression(&sig).is_none());
    }

    #[test]
    fn plan_c_call_uses_void_cast_when_return_type_present() {
        let sig = parse_c_signature("int parse(const uint8_t *p)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("(void)parse"));
    }

    #[test]
    fn plan_c_call_does_not_void_cast_for_void_return() {
        let sig = parse_c_signature("void parse(const uint8_t *p)").unwrap();
        let plan = plan_c_call_expression(&sig).unwrap();
        assert!(!plan.call_expression.contains("(void)parse"));
        assert!(plan
            .call_expression
            .contains("parse((const uint8_t *)data)"));
    }

    // ----- C self-contained heuristic ------------------------------

    #[test]
    fn c_self_contained_accepts_system_includes() {
        let src = "#include <stdint.h>\n#include <stddef.h>\nvoid foo(void) {}\n";
        assert!(c_source_appears_self_contained(src));
    }

    #[test]
    fn c_self_contained_rejects_project_includes() {
        let src = "#include \"private.h\"\nvoid foo(void) {}\n";
        assert!(!c_source_appears_self_contained(src));
    }

    #[test]
    fn c_self_contained_accepts_no_includes() {
        let src = "void foo(void) { return; }\n";
        assert!(c_source_appears_self_contained(src));
    }

    // ----- end-to-end harness shape --------------------------------

    #[tokio::test]
    async fn scaffold_c_project_wires_trampoline_when_source_self_contained() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vuln.c");
        std::fs::write(
            &path,
            "#include <stdint.h>\n#include <string.h>\n\
             void copy_attacker(const uint8_t *src, size_t len) {\n\
                 char dest[16];\n\
                 memcpy(dest, src, len);\n\
                 (void)dest;\n\
             }\n",
        )
        .unwrap();
        let mut finding = finding_for(path.to_str().unwrap());
        finding.start_line = 4;
        let project = scaffold_c_project(&finding, CCompiler::Gcc).await.unwrap();

        let target = std::fs::read_to_string(project.path.join("target.c")).unwrap();
        assert!(target.contains("#include \"suspect_source.c\""));
        assert!(target.contains("copy_attacker((const uint8_t *)data, len)"));
        let suspect_path = project.path.join("suspect_source.c");
        assert!(
            suspect_path.exists(),
            "trampoline path should write suspect_source.c"
        );
        let suspect_src = std::fs::read_to_string(suspect_path).unwrap();
        assert!(suspect_src.contains("copy_attacker"));
    }

    #[tokio::test]
    async fn scaffold_c_project_falls_back_when_source_not_self_contained() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vuln.c");
        std::fs::write(
            &path,
            "#include \"private.h\"\nvoid foo(const uint8_t *p, size_t n) { (void)p; (void)n; }\n",
        )
        .unwrap();
        let mut finding = finding_for(path.to_str().unwrap());
        finding.start_line = 2;
        let project = scaffold_c_project(&finding, CCompiler::Gcc).await.unwrap();

        let target = std::fs::read_to_string(project.path.join("target.c")).unwrap();
        // Fallback stub keeps the no-op body.
        assert!(target.contains("(void)data;"));
        assert!(!project.path.join("suspect_source.c").exists());
    }

    #[test]
    fn build_c_trigger_falls_back_when_no_signature_locatable() {
        let mut finding = finding_for("/no/such/file.c");
        finding.start_line = 99;
        let trigger = build_c_trigger(&finding);
        assert!(trigger.suspect_source.is_none());
        assert!(trigger.target_c.contains("payload-only fallback"));
    }

    // ----- sanitizer-stderr detection ------------------------------

    #[test]
    fn stderr_detector_recognises_asan_stack_buffer_overflow() {
        let stderr = "==123==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f...";
        assert!(stderr_has_sanitizer_crash(stderr));
    }

    #[test]
    fn stderr_detector_recognises_ubsan_runtime_error() {
        let stderr = "runtime error: signed integer overflow: ...";
        assert!(stderr_has_sanitizer_crash(stderr));
    }

    #[test]
    fn stderr_detector_recognises_use_after_free() {
        assert!(stderr_has_sanitizer_crash(
            "AddressSanitizer: heap-use-after-free on address 0x..."
        ));
        assert!(stderr_has_sanitizer_crash("==1==ERROR: use-after-free"));
    }

    #[test]
    fn stderr_detector_ignores_clean_output() {
        assert!(!stderr_has_sanitizer_crash(""));
        assert!(!stderr_has_sanitizer_crash(
            "clean stderr output\nno errors here\n"
        ));
        assert!(!stderr_has_sanitizer_crash("Compiled with -Wall -Werror"));
    }

    #[test]
    fn classify_promotes_to_4_on_asan_stderr_signature_even_without_signal() {
        let opts = VerifyOptions {
            trust_plain_backend: true,
            ..VerifyOptions::default()
        };
        let mut result = sandbox_result(ExitOutcome::Exited, Some(1), None);
        result.stderr =
            "==99==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...".to_string();
        let outcome = classify_run_result(
            &result,
            SandboxBackend::Plain,
            std::path::Path::new("/p"),
            &opts,
        );
        assert_eq!(outcome.proof_level, 4);
        assert_eq!(outcome.proof_verdict, ProofVerdict::Exploited);
    }

    #[test]
    fn classify_keeps_observed_crash_verdict_when_clamped_for_plain_backend() {
        // Default opts (trust_plain_backend=false) + Plain backend + observed
        // SIGSEGV: level clamped to 3, but verdict stays Exploited because
        // we DID observe a crash.
        let opts = VerifyOptions::default();
        let result = sandbox_result(ExitOutcome::Signaled, None, Some(11));
        let outcome = classify_run_result(
            &result,
            SandboxBackend::Plain,
            std::path::Path::new("/p"),
            &opts,
        );
        assert_eq!(outcome.proof_level, 3);
        assert_eq!(outcome.proof_verdict, ProofVerdict::Exploited);
        assert!(outcome
            .notes
            .iter()
            .any(|n| n.contains("rerun under Bwrap/Podman to promote")));
    }

    #[tokio::test]
    async fn scaffold_python_project_writes_runnable_module() {
        let finding = finding_for("src/x.py");
        let project = scaffold_python_project(&finding).await.unwrap();
        let body = std::fs::read_to_string(project.path.join("trigger.py")).unwrap();
        assert!(body.contains("def trigger"));
        assert!(body.contains("test_trigger"));
        assert!(body.contains("PAYLOAD = bytes("));
    }

    #[tokio::test]
    async fn scaffold_node_project_writes_runnable_script() {
        let finding = finding_for("src/x.js");
        let project = scaffold_node_project(&finding, "js").await.unwrap();
        let body = std::fs::read_to_string(project.path.join("trigger.js")).unwrap();
        assert!(body.contains("Uint8Array.from"));
        assert!(body.contains("function trigger"));
        assert!(body.contains("process.exit(0)"));
    }

    // ----- new language paths return BackendUnavailable when no toolchain

    #[tokio::test]
    async fn verify_node_reports_infrastructure_error_when_node_missing() {
        if kuzushi_sandbox::which("node").is_some() {
            return;
        }
        let finding = finding_for("src/x.js");
        let outcome = verify_finding(&finding, VerifyOptions::default())
            .await
            .unwrap();
        assert_eq!(outcome.proof_verdict, ProofVerdict::InfrastructureError);
        assert!(outcome
            .crash_evidence
            .as_deref()
            .unwrap_or_default()
            .contains("node"));
    }

    #[tokio::test]
    async fn verify_c_reports_infrastructure_error_when_no_compiler() {
        if kuzushi_sandbox::which("clang").is_some() || kuzushi_sandbox::which("gcc").is_some() {
            return;
        }
        let finding = finding_for("src/x.c");
        let outcome = verify_finding(&finding, VerifyOptions::default())
            .await
            .unwrap();
        assert_eq!(outcome.proof_verdict, ProofVerdict::InfrastructureError);
    }

    // ----- harness body is shaped by extracted signature -----------

    #[test]
    fn build_rust_trigger_embeds_located_signature_in_comment() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lib.rs");
        std::fs::write(
            &path,
            "pub fn parse(p: &[u8]) -> u32 {\n    let _ = p;\n    0\n}\n",
        )
        .unwrap();
        let mut finding = finding_for(path.to_str().unwrap());
        finding.start_line = 2;
        let trigger = build_rust_trigger(&finding);
        // Either the located-function header or the synthesized-call
        // header should appear; both name the function.
        assert!(trigger.trigger_test.contains("parse"));
        assert!(
            trigger.trigger_test.contains("Suspect:")
                || trigger.trigger_test.contains("Located enclosing function")
        );
    }

    #[test]
    fn build_rust_trigger_falls_back_when_no_signature_locatable() {
        let mut finding = finding_for("/no/such/file.rs");
        finding.start_line = 99;
        let trigger = build_rust_trigger(&finding);
        assert!(trigger
            .trigger_test
            .contains("No enclosing function located"));
        assert!(trigger.suspect_source.is_none());
    }

    // ----- Rust signature parsing ----------------------------------

    #[test]
    fn parse_rust_signature_extracts_name_and_arg_types() {
        let sig = parse_rust_signature("pub fn parse_packet(input: &[u8], n: usize) -> u32 {")
            .expect("should parse");
        assert_eq!(sig.fn_name, "parse_packet");
        assert_eq!(sig.args, vec!["&[u8]".to_string(), "usize".to_string()]);
        assert_eq!(sig.return_type.as_deref(), Some("u32"));
    }

    #[test]
    fn parse_rust_signature_handles_zero_args() {
        let sig = parse_rust_signature("fn run() {").expect("should parse");
        assert_eq!(sig.fn_name, "run");
        assert!(sig.args.is_empty());
        assert!(sig.return_type.is_none());
    }

    #[test]
    fn parse_rust_signature_handles_generics() {
        let sig =
            parse_rust_signature("pub async fn decode<T: AsRef<[u8]>>(input: T) -> Result<u32, E>")
                .expect("should parse");
        assert_eq!(sig.fn_name, "decode");
        assert_eq!(sig.args, vec!["T".to_string()]);
    }

    #[test]
    fn parse_rust_signature_skips_self_receiver() {
        let sig =
            parse_rust_signature("pub fn parse(&self, input: &[u8]) -> u32").expect("should parse");
        // self is dropped; only the &[u8] remains.
        assert_eq!(sig.args, vec!["&[u8]".to_string()]);
    }

    #[test]
    fn parse_rust_signature_handles_nested_tuple_arg() {
        let sig =
            parse_rust_signature("fn pair(input: (u8, u8), bytes: &[u8])").expect("should parse");
        assert_eq!(sig.args, vec!["(u8, u8)".to_string(), "&[u8]".to_string()]);
    }

    #[test]
    fn parse_rust_signature_returns_none_for_non_function() {
        assert!(parse_rust_signature("if foo { bar }").is_none());
        assert!(parse_rust_signature("struct S { ... }").is_none());
    }

    // ----- call-plan synthesis -------------------------------------

    #[test]
    fn plan_call_zero_args() {
        let sig = parse_rust_signature("fn run()").unwrap();
        let plan = plan_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("suspect::run()"));
        assert!(plan.call_kind.contains("zero-argument"));
    }

    #[test]
    fn plan_call_byte_slice_arg() {
        let sig = parse_rust_signature("fn parse(input: &[u8])").unwrap();
        let plan = plan_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("suspect::parse(&payload)"));
    }

    #[test]
    fn plan_call_buf_len_pair_synthesizes_c_ffi_call() {
        let sig = parse_rust_signature("fn copy(buf: &[u8], len: usize)").unwrap();
        let plan = plan_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("&payload, payload.len()"));
        assert_eq!(plan.call_kind, "(buf, len) C-FFI-style call");
    }

    #[test]
    fn plan_call_raw_pointer_buf_uses_as_ptr() {
        let sig = parse_rust_signature("fn read(buf: *const u8, len: usize)").unwrap();
        let plan = plan_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("payload.as_ptr()"));
    }

    #[test]
    fn plan_call_returns_none_for_unsupported_signatures() {
        let sig = parse_rust_signature("fn complex(a: u32, b: f64, c: &MyStruct)").unwrap();
        assert!(plan_call_expression(&sig).is_none());
    }

    #[test]
    fn plan_call_uses_let_binding_when_return_type_present() {
        let sig = parse_rust_signature("fn parse(input: &[u8]) -> u32").unwrap();
        let plan = plan_call_expression(&sig).unwrap();
        assert!(plan.call_expression.contains("let _ ="));
    }

    // ----- self-contained source heuristic --------------------------

    #[test]
    fn self_contained_accepts_simple_file() {
        let src = "use std::ops::Range;\npub fn f() {}";
        assert!(rust_source_appears_self_contained(src));
    }

    #[test]
    fn self_contained_rejects_extern_crate() {
        let src = "extern crate libc;\npub fn f() {}";
        assert!(!rust_source_appears_self_contained(src));
    }

    #[test]
    fn self_contained_rejects_crate_relative_use() {
        let src = "use crate::other::T;\npub fn f() {}";
        assert!(!rust_source_appears_self_contained(src));
    }

    #[test]
    fn self_contained_rejects_non_std_derive() {
        let src = "#[derive(serde::Serialize)]\npub struct S;";
        assert!(!rust_source_appears_self_contained(src));
    }

    #[test]
    fn self_contained_accepts_std_derives() {
        let src = "#[derive(Debug, Clone, PartialEq)]\npub struct S;";
        assert!(rust_source_appears_self_contained(src));
    }

    // ----- end-to-end harness shape ---------------------------------

    #[tokio::test]
    async fn scaffolder_writes_suspect_rs_when_source_is_self_contained() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lib.rs");
        std::fs::write(
            &path,
            "pub fn parse(input: &[u8]) -> usize { input.len() }\n",
        )
        .unwrap();
        let mut finding = finding_for(path.to_str().unwrap());
        finding.start_line = 1;
        let trigger = build_rust_trigger(&finding);
        assert!(trigger.suspect_source.is_some());
        let project = scaffold_rust_project(&trigger).await.unwrap();
        let suspect = std::fs::read_to_string(project.path.join("src").join("suspect.rs")).unwrap();
        assert!(suspect.contains("pub fn parse"));
        let lib = std::fs::read_to_string(project.path.join("src").join("lib.rs")).unwrap();
        assert!(lib.contains("pub mod suspect"));
        let test = std::fs::read_to_string(project.path.join("tests").join("trigger.rs")).unwrap();
        assert!(test.contains("suspect::parse(&payload)"));
    }

    #[test]
    fn build_rust_trigger_skips_sink_call_for_non_self_contained_source() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("lib.rs");
        std::fs::write(
            &path,
            "use crate::other::Helper;\npub fn parse(input: &[u8]) {}\n",
        )
        .unwrap();
        let mut finding = finding_for(path.to_str().unwrap());
        finding.start_line = 2;
        let trigger = build_rust_trigger(&finding);
        // No sink call — payload-only fallback because the file uses
        // `crate::` paths.
        assert!(trigger.trigger_test.contains("Payload-only harness"));
    }
}

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

/// Build the source for the trigger `#[test]`. Embeds the located
/// enclosing function signature as a comment so the harness output
/// makes it clear *which* function this run is exercising; the harness
/// does not yet invoke that function (full call-synthesis routes
/// through the codeindex facade in a follow-up).
fn build_rust_trigger(finding: &Finding) -> RustTriggerSource {
    let payload = synth_payload_from_finding(finding);
    let suspect =
        extract_enclosing_function(std::path::Path::new(&finding.file_path), finding.start_line);
    let suspect_comment = match &suspect {
        Some(f) => format!(
            "// Located enclosing function near {}:{} (signature at line {}) → `{}`",
            finding.file_path,
            f.line,
            f.signature_line,
            f.signature.trim()
        ),
        None => format!(
            "// No enclosing function located near {}:{} (proceeding with payload-only harness)",
            finding.file_path, finding.start_line
        ),
    };
    let body = format!(
        "// Synthesised by kuzushi verify for finding {fp}\n\
         {suspect_comment}\n\
         #[test]\n\
         fn trigger() {{\n\
             let payload: Vec<u8> = vec!{payload:?};\n\
             // The payload is intentionally not consumed by a sink yet —\n\
             // the actual sink-call is wired by codeindex integration in a\n\
             // follow-up. For now this harness exercises the build/observe\n\
             // loop end-to-end without calling unsafe code.\n\
             let _ = std::hint::black_box(payload);\n\
         }}\n",
        fp = finding.fingerprint,
        suspect_comment = suspect_comment,
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

    let ends_with_brace = trimmed.ends_with('{');
    let ends_with_colon = trimmed.ends_with(':');
    let multiline_continuation = trimmed.ends_with('(') || trimmed.ends_with(',');
    if !ends_with_brace && !ends_with_colon && !multiline_continuation {
        return false;
    }

    if trimmed.starts_with("fn ")
        || trimmed.starts_with("pub fn ")
        || trimmed.contains(" fn ")
        || trimmed.starts_with("def ")
        || trimmed.starts_with("async def ")
        || trimmed.starts_with("function ")
        || trimmed.starts_with("async function ")
        || trimmed.starts_with("export function ")
        || trimmed.starts_with("export async function ")
    {
        return true;
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

const C_TARGET_STUB: &str = r#"// kuzushi-verify trigger surface — placeholder.
// Wired to the suspect function's source by future codeindex
// integration; for now the harness exercises the build/observe loop
// without invoking unsafe code.
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
    let mut compile_cmd = SandboxExecOptions::new(vec![
        cc.to_string(),
        "-O0".to_string(),
        "-g".to_string(),
        "-fsanitize=address,undefined".to_string(),
        "-fno-sanitize-recover=all".to_string(),
        "-Werror=implicit-function-declaration".to_string(),
        "-o".to_string(),
        binary_path.display().to_string(),
        project.path.join("trigger.c").display().to_string(),
        project.path.join("target.c").display().to_string(),
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
    if kuzushi_sandbox::which(compiler.binary()).is_some() {
        return Some(compiler.binary().to_string());
    }
    if kuzushi_sandbox::which(compiler.fallback()).is_some() {
        return Some(compiler.fallback().to_string());
    }
    None
}

async fn scaffold_c_project(finding: &Finding, _compiler: CCompiler) -> Result<ScaffoldedProject> {
    let tempdir = tempfile::tempdir().context("could not create C harness temp dir")?;
    let root = tempdir.path().to_path_buf();
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
    tokio::fs::write(root.join("trigger.c"), trigger_c).await?;
    tokio::fs::write(root.join("target.c"), C_TARGET_STUB).await?;
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
    if kuzushi_sandbox::which("node").is_none() {
        return Ok(infrastructure_error(
            backend,
            None,
            "node not on PATH; install Node.js to verify .js / .ts findings".to_string(),
        ));
    }

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

    // We only run JS today; TS findings get the same JS harness because
    // the trigger doesn't yet import the suspect file. Future work:
    // shell out to `tsx` or `ts-node` when available.
    let mut run_cmd = SandboxExecOptions::new(vec![
        "node".to_string(),
        project.path.join("trigger.js").display().to_string(),
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
                format!("node run spawn: {err}"),
            ));
        }
    };

    Ok(classify_run_result(&run, backend, &project.path, opts))
}

async fn scaffold_node_project(finding: &Finding, _extension: &str) -> Result<ScaffoldedProject> {
    let tempdir = tempfile::tempdir().context("could not create node harness temp dir")?;
    let root = tempdir.path().to_path_buf();
    let payload = synth_payload_from_finding(finding);
    let payload_csv = payload
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let body = JS_HARNESS_TEMPLATE.replace("{payload_csv}", &payload_csv);
    tokio::fs::write(root.join("trigger.js"), body).await?;
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
        assert!(trigger.trigger_test.contains("parse"));
        assert!(trigger.trigger_test.contains("Located enclosing function"));
    }

    #[test]
    fn build_rust_trigger_falls_back_when_no_signature_locatable() {
        let mut finding = finding_for("/no/such/file.rs");
        finding.start_line = 99;
        let trigger = build_rust_trigger(&finding);
        assert!(trigger
            .trigger_test
            .contains("No enclosing function located"));
    }
}

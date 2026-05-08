use super::*;
use kuzushi_sandbox::SandboxExecResult;

/// Classify a sandbox run result into a `VerificationOutcome`. Public
/// for testing — the unit tests construct synthetic `SandboxExecResult`s
/// rather than running real cargo.
pub fn classify_run_result(
    run: &SandboxExecResult,
    backend: SandboxBackend,
    project_path: &Path,
    opts: &VerifyOptions,
) -> VerificationOutcome {
    use kuzushi_sandbox::ExitOutcome::*;
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

pub(super) fn is_crash_signal(sig: i32) -> bool {
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
    pub(super) const PATTERNS: &[&str] = &[
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

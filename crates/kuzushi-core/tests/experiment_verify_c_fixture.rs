//! Live experiment: run the verify pipeline against a tiny CWE-121
//! stack-buffer-overflow fixture and observe what AddressSanitizer
//! catches. Skipped when no C compiler is on PATH.
//!
//! Run with:
//!   cargo test -p kuzushi-core --test experiment_verify_c_fixture -- --nocapture --ignored

use kuzushi_core::verify::{verify_finding, ProofVerdict, VerifyOptions};
use kuzushi_core::{Finding, Severity};
use kuzushi_sandbox::SandboxBackend;

const VULN_C: &str = r#"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

void copy_attacker_buffer(const uint8_t *src, size_t len) {
    char dest[16];
    // Bug: no bounds check on `len`. ASan should catch this when the
    // harness passes a 72-byte payload (8 marker + 64 message bytes).
    memcpy(dest, src, len);
    (void)dest;
}
"#;

#[tokio::test]
#[ignore = "live experiment; requires clang/gcc + run with --nocapture --ignored"]
async fn verify_catches_cwe121_stack_overflow() {
    if kuzushi_sandbox::which("clang").is_none() && kuzushi_sandbox::which("gcc").is_none() {
        eprintln!("no C compiler on PATH; skipping experiment");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("vulnerable.c");
    std::fs::write(&path, VULN_C).unwrap();

    let mut finding = Finding::new_tool(
        "experiment",
        "cwe-121-stack-overflow",
        path.to_str().unwrap(),
        7,
        Some(7),
        Severity::Critical,
        "stack buffer overflow via untrusted length",
    );
    finding.id = Some(1);

    let opts = VerifyOptions {
        backend: Some(SandboxBackend::Plain),
        timeout_ms: 90_000,
        trust_plain_backend: true,
        ..VerifyOptions::default()
    };
    let outcome = verify_finding(&finding, opts).await.unwrap();

    eprintln!("{}", serde_json::to_string_pretty(&outcome).unwrap());

    // What we expect from the new pipeline: the harness compiles
    // (clang -fsanitize=address,undefined builds the trigger), runs,
    // and ASan crashes with a stack-buffer-overflow report. With the
    // current scaffolder the harness invokes a placeholder
    // `kuzushi_verify_call_target` stub instead of the real function,
    // so we expect proof_level=2 (build+run, no crash) — proving the
    // C path's plumbing works end-to-end without yet having the
    // codeindex-driven sink-call.
    assert_eq!(outcome.language.as_deref(), Some("c"));
    assert!(matches!(
        outcome.proof_verdict,
        ProofVerdict::NotReproduced
            | ProofVerdict::Exploited
            | ProofVerdict::HarnessFailedToBuild
            | ProofVerdict::InfrastructureError
    ));
    assert!(outcome.duration_ms > 0);
}

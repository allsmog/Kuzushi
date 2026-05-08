use super::*;

pub(crate) fn compile_failure_outcome(
    backend: SandboxBackend,
    project: &ScaffoldedProject,
    compile: &kuzushi_sandbox::SandboxExecResult,
) -> Option<VerificationOutcome> {
    (compile.exit_code != Some(0)).then(|| {
        harness_failed_to_build(
            backend,
            project.path.clone(),
            compile.stderr.clone(),
            compile.duration_ms,
        )
    })
}

pub(in crate::verification) fn node_run_command(
    project: &ScaffoldedProject,
    opts: &VerifyOptions,
    runner: NodeRunner,
) -> SandboxExecOptions {
    let trigger_name = runner.trigger_name();
    let mut argv = runner.argv;
    argv.push(project.path.join(trigger_name).display().to_string());
    project_command(project, opts, argv)
}

pub(crate) fn c_compile_command(
    project: &ScaffoldedProject,
    opts: &VerifyOptions,
    compiler: &str,
    binary_path: &Path,
) -> SandboxExecOptions {
    let mut argv = vec![
        compiler.to_string(),
        "-O0".to_string(),
        "-g".to_string(),
        "-Werror=implicit-function-declaration".to_string(),
    ];
    argv.extend(c_sanitizer_flags(compiler).into_iter().map(str::to_string));
    argv.extend([
        "-o".to_string(),
        binary_path.display().to_string(),
        project.path.join("trigger.c").display().to_string(),
        project.path.join("target.c").display().to_string(),
    ]);
    project_command(project, opts, argv)
}

pub(crate) fn c_run_command(
    project: &ScaffoldedProject,
    opts: &VerifyOptions,
    binary_path: &Path,
) -> SandboxExecOptions {
    project_command(project, opts, vec![binary_path.display().to_string()])
}

pub(crate) fn rust_test_argv() -> Vec<String> {
    vec![
        "cargo".to_string(),
        "test".to_string(),
        "--offline".to_string(),
        "--".to_string(),
        "--nocapture".to_string(),
    ]
}

pub(crate) fn infrastructure_error(
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

pub(crate) fn harness_failed_to_build(
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

#[derive(Debug)]
pub(crate) struct ScaffoldedProject {
    pub(crate) path: PathBuf,
    /// Held to keep the temp dir alive for the lifetime of verify().
    /// Field name with `_` prefix is intentional: it's never read but
    /// must not be dropped early.
    pub(crate) _tempdir: tempfile::TempDir,
}

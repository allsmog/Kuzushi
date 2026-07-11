use super::*;

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
    let extension = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    known_language(&extension).unwrap_or_else(|| unknown_language(extension))
}

fn known_language(extension: &str) -> Option<Lang> {
    language_kind_table()
        .iter()
        .find(|(extensions, _)| extensions.contains(&extension))
        .map(|(_, language)| language.clone())
}

fn language_kind_table() -> &'static [(&'static [&'static str], Lang)] {
    &[
        (&["rs"], Lang::Rust),
        (&["c", "h"], Lang::C),
        (&["cc", "cpp", "cxx", "hh", "hpp", "hxx"], Lang::Cpp),
        (&["py", "pyi"], Lang::Python),
        (&["js", "mjs", "cjs"], Lang::JavaScript),
        (&["ts", "tsx", "mts", "cts"], Lang::TypeScript),
    ]
}

fn unknown_language(extension: String) -> Lang {
    if extension.is_empty() {
        Lang::Other("unknown".to_string())
    } else {
        Lang::Other(extension)
    }
}

pub(crate) async fn verify_rust(
    finding: &Finding,
    backend: SandboxBackend,
    opts: &VerifyOptions,
    workspace_root: &Path,
) -> Result<VerificationOutcome> {
    let trigger = match build_rust_trigger(finding, workspace_root) {
        Ok(trigger) => trigger,
        Err(error) => return Ok(scaffold_error(backend, "Rust source input", error)),
    };
    let project = match scaffold_rust_project(&trigger).await {
        Ok(p) => p,
        Err(err) => return Ok(scaffold_error(backend, "scaffold", err)),
    };

    // Compile-only first; saves wallclock when the harness can't even
    // build (no need to also run it).
    let compile = match sandbox_exec(backend, rust_compile_command(&project, opts)).await {
        Ok(r) => r,
        Err(err) => return Ok(project_error(backend, &project, "sandbox spawn", err)),
    };
    if let Some(outcome) = compile_failure_outcome(backend, &project, &compile) {
        return Ok(outcome);
    }

    let run = match sandbox_exec(backend, rust_run_command(&project, opts)).await {
        Ok(r) => r,
        Err(err) => return Ok(project_error(backend, &project, "sandbox spawn", err)),
    };

    Ok(classify_run_result(&run, backend, &project.path, opts))
}

pub(crate) fn rust_compile_command(
    project: &ScaffoldedProject,
    opts: &VerifyOptions,
) -> SandboxExecOptions {
    project_command(
        project,
        opts,
        vec![
            "cargo".to_string(),
            "test".to_string(),
            "--no-run".to_string(),
            "--offline".to_string(),
        ],
    )
}

pub(crate) fn rust_run_command(
    project: &ScaffoldedProject,
    opts: &VerifyOptions,
) -> SandboxExecOptions {
    project_command(project, opts, rust_test_argv())
}

pub(crate) fn project_command(
    project: &ScaffoldedProject,
    opts: &VerifyOptions,
    argv: Vec<String>,
) -> SandboxExecOptions {
    let mut command = SandboxExecOptions::new(argv);
    command.timeout_ms = opts.timeout_ms;
    command.workdir = Some(project.path.clone());
    command.read_write_mounts = project_rw_mounts(project);
    command
}

pub(crate) fn project_rw_mounts(project: &ScaffoldedProject) -> Vec<MountSpec> {
    vec![MountSpec {
        host_path: project.path.clone(),
        guest_path: project.path.clone(),
    }]
}

pub(crate) fn scaffold_error(
    backend: SandboxBackend,
    label: &str,
    err: impl std::fmt::Display,
) -> VerificationOutcome {
    infrastructure_error(backend, None, format!("{label}: {err}"))
}

pub(crate) fn project_error(
    backend: SandboxBackend,
    project: &ScaffoldedProject,
    label: &str,
    err: impl std::fmt::Display,
) -> VerificationOutcome {
    infrastructure_error(
        backend,
        Some(project.path.clone()),
        format!("{label}: {err}"),
    )
}

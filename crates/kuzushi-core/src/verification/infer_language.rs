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
    source_identity: &crate::workflow_attempts::TargetContentIdentity,
    payload: Option<&[u8]>,
) -> Result<VerificationOutcome> {
    let trigger = match rust_trigger_for_payload(finding, workspace_root, payload) {
        Ok(trigger) => trigger,
        Err(error) => return Ok(scaffold_error(backend, "Rust source input", error)),
    };
    if trigger.fidelity != HarnessFidelity::Faithful {
        return Ok(not_attempted_for_harness(backend, trigger.fidelity));
    }
    let has_suspect_source = trigger.suspect_source.is_some();
    let mut project = match scaffold_rust_project(&trigger).await {
        Ok(project) => project,
        Err(error) => return Ok(scaffold_error(backend, "scaffold", error)),
    };
    if let Err(error) = persist_rust_reproducer(
        &mut project,
        workspace_root,
        source_identity,
        has_suspect_source,
    ) {
        return Ok(project_error(
            backend,
            &project,
            "reproducer persistence",
            error,
        ));
    }
    execute_rust_project(backend, opts, &project).await
}

fn rust_trigger_for_payload(
    finding: &Finding,
    workspace_root: &Path,
    payload: Option<&[u8]>,
) -> Result<RustTriggerSource> {
    payload.map_or_else(
        || build_rust_trigger(finding, workspace_root),
        |payload| build_rust_trigger_with_payload(finding, workspace_root, payload),
    )
}

fn persist_rust_reproducer(
    project: &mut ScaffoldedProject,
    workspace_root: &Path,
    source_identity: &crate::workflow_attempts::TargetContentIdentity,
    has_suspect_source: bool,
) -> Result<()> {
    let mut reproducer_files = vec!["Cargo.toml", "src/lib.rs", "tests/trigger.rs"];
    if has_suspect_source {
        reproducer_files.push("src/suspect.rs");
    }
    let reproducer = persist_empirical_reproducer(
        workspace_root,
        &project.path,
        "rust",
        rust_reproducer_invocation(),
        &reproducer_files,
        &project.payload,
    )?;
    project.provenance = Some(provenance_with_reproducer(source_identity, reproducer));
    Ok(())
}

fn rust_reproducer_invocation() -> ReproducerInvocation {
    ReproducerInvocation {
        compile_argv: vec![
            "cargo".to_string(),
            "test".to_string(),
            "--no-run".to_string(),
            "--offline".to_string(),
        ],
        execute_argv: rust_test_argv(),
    }
}

async fn execute_rust_project(
    backend: SandboxBackend,
    opts: &VerifyOptions,
    project: &ScaffoldedProject,
) -> Result<VerificationOutcome> {
    // Compile-only first; saves wallclock when the harness can't even
    // build (no need to also run it).
    let compile = match sandbox_exec(backend, rust_compile_command(project, opts)).await {
        Ok(result) => result,
        Err(error) => return Ok(project_error(backend, project, "sandbox spawn", error)),
    };
    if let Some(outcome) = compile_failure_outcome(backend, project, &compile) {
        return Ok(project.bind(outcome));
    }

    if let Err(error) = prepare_sink_marker(&project.path) {
        return Ok(project_error(
            backend,
            &project,
            "sink marker preparation",
            error,
        ));
    }

    let run = match sandbox_exec(backend, rust_run_command(project, opts)).await {
        Ok(result) => result,
        Err(error) => return Ok(project_error(backend, project, "sandbox spawn", error)),
    };

    Ok(project.bind(classify_run_result(
        &run,
        backend,
        &project.path,
        project.fidelity,
    )))
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
    let mut command = project_command(project, opts, rust_test_argv());
    configure_sink_marker(&mut command, &project.path);
    command
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
    project.bind(infrastructure_error(
        backend,
        Some(project.path.clone()),
        format!("{label}: {err}"),
    ))
}

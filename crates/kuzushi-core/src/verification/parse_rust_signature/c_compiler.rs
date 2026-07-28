use super::*;

#[derive(Debug, Clone, Copy)]
pub(in crate::verification) enum CCompiler {
    Gcc,
    Gpp,
}

impl CCompiler {
    pub(in crate::verification) fn binary(self) -> &'static str {
        // Prefer clang when available because of richer ASan output;
        // fall back to gcc/g++. We let `which` decide at runtime.
        match self {
            Self::Gcc => "clang",
            Self::Gpp => "clang++",
        }
    }

    pub(in crate::verification) fn fallback(self) -> &'static str {
        match self {
            Self::Gcc => "gcc",
            Self::Gpp => "g++",
        }
    }
}

pub(in crate::verification) const C_HARNESS_TEMPLATE: &str = r#"// kuzushi-verify C/C++ trigger harness
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
/// payload-only fallback. Verification rejects this fidelity before compile
/// or execution.
pub(in crate::verification) const C_TARGET_STUB: &str = r#"// kuzushi-verify payload-only fallback.
// The suspect source could not be wired into the harness because either
// the file was unreadable, the signature could not be parsed, or it
// uses project-relative includes that need the codeindex facade to
// resolve. Verify returns NotAttempted before compiling this scaffold.
#include <stdint.h>
#include <stddef.h>

void kuzushi_verify_call_target(const uint8_t *data, size_t len) {
    (void)data;
    (void)len;
}
"#;

pub(in crate::verification) async fn verify_c_like(
    finding: &Finding,
    backend: SandboxBackend,
    opts: &VerifyOptions,
    compiler: CCompiler,
    workspace_root: &Path,
    source_identity: &crate::workflow_attempts::TargetContentIdentity,
    payload: Option<&[u8]>,
) -> Result<VerificationOutcome> {
    let mut project =
        match scaffold_c_project_for_payload(finding, compiler, workspace_root, payload).await {
            Ok(project) => project,
            Err(error) => return Ok(scaffold_error(backend, "c scaffold", error)),
        };
    if project.fidelity != HarnessFidelity::Faithful {
        return Ok(not_attempted_for_harness(backend, project.fidelity));
    }
    if let Err(error) =
        persist_c_reproducer(&mut project, compiler, workspace_root, source_identity)
    {
        return Ok(project_error(
            backend,
            &project,
            "reproducer persistence",
            error,
        ));
    }
    let Some(cc) = pick_c_compiler(compiler) else {
        return Ok(missing_c_compiler(backend, &project));
    };
    execute_c_project(backend, opts, &project, &cc).await
}

async fn scaffold_c_project_for_payload(
    finding: &Finding,
    compiler: CCompiler,
    workspace_root: &Path,
    payload: Option<&[u8]>,
) -> Result<ScaffoldedProject> {
    match payload {
        Some(payload) => {
            scaffold_c_project_with_payload(finding, compiler, workspace_root, payload).await
        }
        None => scaffold_c_project(finding, compiler, workspace_root).await,
    }
}

fn persist_c_reproducer(
    project: &mut ScaffoldedProject,
    compiler: CCompiler,
    workspace_root: &Path,
    source_identity: &crate::workflow_attempts::TargetContentIdentity,
) -> Result<()> {
    let reproducer = persist_empirical_reproducer(
        workspace_root,
        &project.path,
        c_reproducer_language(compiler),
        c_reproducer_invocation(),
        &c_reproducer_files(project),
        &project.payload,
    )?;
    project.provenance = Some(provenance_with_reproducer(source_identity, reproducer));
    Ok(())
}

fn c_reproducer_language(compiler: CCompiler) -> &'static str {
    match compiler {
        CCompiler::Gcc => "c",
        CCompiler::Gpp => "cpp",
    }
}

fn c_reproducer_files(project: &ScaffoldedProject) -> Vec<&'static str> {
    let mut files = vec!["target.c", "trigger.c"];
    if project.path.join("suspect_source.c").is_file() {
        files.push("suspect_source.c");
    }
    files
}

fn c_reproducer_invocation() -> ReproducerInvocation {
    ReproducerInvocation {
        compile_argv: vec![
            "${CC}".to_string(),
            "-O0".to_string(),
            "-g".to_string(),
            "-Werror=implicit-function-declaration".to_string(),
            "${SANITIZER_FLAGS}".to_string(),
            "-o".to_string(),
            "trigger".to_string(),
            "trigger.c".to_string(),
            "target.c".to_string(),
        ],
        execute_argv: vec!["./trigger".to_string()],
    }
}

async fn execute_c_project(
    backend: SandboxBackend,
    opts: &VerifyOptions,
    project: &ScaffoldedProject,
    cc: &str,
) -> Result<VerificationOutcome> {
    let binary_path = project.path.join("trigger");
    let compile_command = c_compile_command(project, opts, cc, &binary_path);
    let compile = match sandbox_exec(backend, compile_command).await {
        Ok(result) => result,
        Err(error) => return Ok(project_error(backend, project, "c compile spawn", error)),
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

    let run = match sandbox_exec(backend, c_run_command(project, opts, &binary_path)).await {
        Ok(result) => result,
        Err(error) => return Ok(project_error(backend, project, "c run spawn", error)),
    };

    Ok(project.bind(classify_run_result(
        &run,
        backend,
        &project.path,
        project.fidelity,
    )))
}

pub(in crate::verification) fn missing_c_compiler(
    backend: SandboxBackend,
    project: &ScaffoldedProject,
) -> VerificationOutcome {
    project.bind(infrastructure_error(
        backend,
        Some(project.path.clone()),
        "no C/C++ compiler on PATH (looked for clang/gcc/clang++/g++)".to_string(),
    ))
}

pub(in crate::verification) fn pick_c_compiler(compiler: CCompiler) -> Option<String> {
    CCompilerAvailability::detect(compiler).pick()
}

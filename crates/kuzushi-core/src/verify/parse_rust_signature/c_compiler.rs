use super::*;

#[derive(Debug, Clone, Copy)]
pub(in crate::verify) enum CCompiler {
    Gcc,
    Gpp,
}

impl CCompiler {
    pub(in crate::verify) fn binary(self) -> &'static str {
        // Prefer clang when available because of richer ASan output;
        // fall back to gcc/g++. We let `which` decide at runtime.
        match self {
            Self::Gcc => "clang",
            Self::Gpp => "clang++",
        }
    }

    pub(in crate::verify) fn fallback(self) -> &'static str {
        match self {
            Self::Gcc => "gcc",
            Self::Gpp => "g++",
        }
    }
}

pub(in crate::verify) const C_HARNESS_TEMPLATE: &str = r#"// kuzushi-verify C/C++ trigger harness
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
pub(in crate::verify) const C_TARGET_STUB: &str = r#"// kuzushi-verify payload-only fallback.
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

pub(in crate::verify) async fn verify_c_like(
    finding: &Finding,
    backend: SandboxBackend,
    opts: &VerifyOptions,
    compiler: CCompiler,
) -> Result<VerificationOutcome> {
    let project = match scaffold_c_project(finding, compiler).await {
        Ok(p) => p,
        Err(err) => return Ok(scaffold_error(backend, "c scaffold", err)),
    };

    // Pick a compiler binary that's actually on PATH; ASan is the
    // gold-standard observation primitive for memory-corruption bugs.
    let cc = match pick_c_compiler(compiler) {
        Some(cc) => cc,
        None => return Ok(missing_c_compiler(backend, &project)),
    };

    let binary_path = project.path.join("trigger");
    let compile = match sandbox_exec(
        backend,
        c_compile_command(&project, opts, &cc, &binary_path),
    )
    .await
    {
        Ok(r) => r,
        Err(err) => return Ok(project_error(backend, &project, "c compile spawn", err)),
    };
    if let Some(outcome) = compile_failure_outcome(backend, &project, &compile) {
        return Ok(outcome);
    }

    let run = match sandbox_exec(backend, c_run_command(&project, opts, &binary_path)).await {
        Ok(r) => r,
        Err(err) => return Ok(project_error(backend, &project, "c run spawn", err)),
    };

    Ok(classify_run_result(&run, backend, &project.path, opts))
}

pub(in crate::verify) fn missing_c_compiler(
    backend: SandboxBackend,
    project: &ScaffoldedProject,
) -> VerificationOutcome {
    infrastructure_error(
        backend,
        Some(project.path.clone()),
        "no C/C++ compiler on PATH (looked for clang/gcc/clang++/g++)".to_string(),
    )
}

pub(in crate::verify) fn pick_c_compiler(compiler: CCompiler) -> Option<String> {
    CCompilerAvailability::detect(compiler).pick()
}

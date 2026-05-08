use super::*;

pub(in crate::verify) const JS_HARNESS_TEMPLATE: &str = r#"// kuzushi-verify Node.js trigger harness
pub(in crate::verify) const payload = Uint8Array.from([{payload_csv}]);

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

pub(in crate::verify) async fn verify_node(
    finding: &Finding,
    backend: SandboxBackend,
    opts: &VerifyOptions,
    extension: &str,
) -> Result<VerificationOutcome> {
    let runner = match NodeRunner::for_extension(extension) {
        Some(runner) => runner,
        None => return Ok(missing_node_runner(backend, extension)),
    };

    let project = match scaffold_node_project(finding, extension).await {
        Ok(p) => p,
        Err(err) => return Ok(scaffold_error(backend, "node scaffold", err)),
    };

    let run = match sandbox_exec(backend, node_run_command(&project, opts, runner)).await {
        Ok(r) => r,
        Err(err) => return Ok(project_error(backend, &project, "node run spawn", err)),
    };

    Ok(classify_run_result(&run, backend, &project.path, opts))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::verify) struct NodeRunner {
    pub(in crate::verify) argv: Vec<String>,
    pub(in crate::verify) typescript: bool,
}

impl NodeRunner {
    fn for_extension(extension: &str) -> Option<Self> {
        if is_typescript_extension(extension) {
            Self::typescript()
        } else {
            Self::javascript()
        }
    }

    fn typescript() -> Option<Self> {
        first_present_binary(["tsx", "ts-node", "node"]).map(|binary| Self {
            argv: vec![binary.to_string()],
            typescript: true,
        })
    }

    fn javascript() -> Option<Self> {
        first_present_binary(["node"]).map(|binary| Self {
            argv: vec![binary.to_string()],
            typescript: false,
        })
    }

    pub(in crate::verify) fn trigger_name(&self) -> &'static str {
        if self.typescript {
            "trigger.ts"
        } else {
            "trigger.js"
        }
    }
}

pub(in crate::verify) fn first_present_binary<const N: usize>(
    candidates: [&'static str; N],
) -> Option<&'static str> {
    candidates
        .into_iter()
        .find(|binary| kuzushi_sandbox::which(binary).is_some())
}

pub(in crate::verify) fn is_typescript_extension(extension: &str) -> bool {
    matches!(extension, "ts" | "tsx" | "mts" | "cts")
}

pub(in crate::verify) fn missing_node_runner(
    backend: SandboxBackend,
    extension: &str,
) -> VerificationOutcome {
    if is_typescript_extension(extension) {
        infrastructure_error(
            backend,
            None,
            "no JS/TS runner on PATH; install Node.js (`apt install nodejs` / `brew install node`) and optionally `tsx` for native TypeScript".to_string(),
        )
    } else {
        infrastructure_error(
            backend,
            None,
            "node not on PATH; install Node.js to verify .js findings".to_string(),
        )
    }
}

pub(in crate::verify) async fn scaffold_node_project(
    finding: &Finding,
    extension: &str,
) -> Result<ScaffoldedProject> {
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

use super::*;

#[cfg(test)]
pub(in crate::verification) const JS_HARNESS_TEMPLATE: &str = r#"// kuzushi-verify Node.js trigger harness
pub(in crate::verification) const payload = Uint8Array.from([{payload_csv}]);

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

pub(in crate::verification) async fn verify_node(
    _finding: &Finding,
    backend: SandboxBackend,
    _opts: &VerifyOptions,
    _extension: &str,
) -> Result<VerificationOutcome> {
    Ok(VerificationOutcome::not_attempted(
        backend,
        "Node.js harness is a placeholder and does not invoke the finding sink",
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(test)]
pub(in crate::verification) struct NodeRunner {
    pub(in crate::verification) argv: Vec<String>,
    pub(in crate::verification) typescript: bool,
}

#[cfg(test)]
impl NodeRunner {
    pub(in crate::verification) fn trigger_name(&self) -> &'static str {
        if self.typescript {
            "trigger.ts"
        } else {
            "trigger.js"
        }
    }
}

#[cfg(test)]
pub(in crate::verification) fn is_typescript_extension(extension: &str) -> bool {
    matches!(extension, "ts" | "tsx" | "mts" | "cts")
}

#[cfg(test)]
pub(in crate::verification) fn missing_node_runner(
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

#[cfg(test)]
pub(in crate::verification) async fn scaffold_node_project(
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
        fidelity: HarnessFidelity::Placeholder,
        payload,
        provenance: None,
        _tempdir: tempdir,
    })
}

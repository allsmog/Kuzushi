use super::*;

#[cfg(test)]
pub(in crate::verification) const PY_HARNESS_TEMPLATE: &str = r#"# kuzushi-verify Python trigger harness
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

pub(in crate::verification) async fn verify_python(
    _finding: &Finding,
    backend: SandboxBackend,
    _opts: &VerifyOptions,
) -> Result<VerificationOutcome> {
    Ok(VerificationOutcome::not_attempted(
        backend,
        "Python harness is a placeholder and does not invoke the finding sink",
    ))
}

#[cfg(test)]
pub(in crate::verification) async fn scaffold_python_project(
    finding: &Finding,
) -> Result<ScaffoldedProject> {
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
        fidelity: HarnessFidelity::Placeholder,
        payload,
        provenance: None,
        _tempdir: tempdir,
    })
}

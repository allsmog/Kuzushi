use super::*;

pub(in crate::verify) const PY_HARNESS_TEMPLATE: &str = r#"# kuzushi-verify Python trigger harness
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

pub(in crate::verify) async fn verify_python(
    finding: &Finding,
    backend: SandboxBackend,
    opts: &VerifyOptions,
) -> Result<VerificationOutcome> {
    if kuzushi_sandbox::which("python3").is_none() && kuzushi_sandbox::which("python").is_none() {
        return Ok(infrastructure_error(
            backend,
            None,
            "no python interpreter on PATH (looked for python3, python)".to_string(),
        ));
    }
    let interpreter = kuzushi_sandbox::which("python3")
        .map(|_| "python3")
        .unwrap_or("python");

    let project = match scaffold_python_project(finding).await {
        Ok(p) => p,
        Err(err) => {
            return Ok(infrastructure_error(
                backend,
                None,
                format!("python scaffold: {err}"),
            ));
        }
    };

    let mut run_cmd = SandboxExecOptions::new(vec![
        interpreter.to_string(),
        project.path.join("trigger.py").display().to_string(),
    ]);
    run_cmd.timeout_ms = opts.timeout_ms;
    run_cmd.workdir = Some(project.path.clone());
    run_cmd.read_write_mounts = vec![MountSpec {
        host_path: project.path.clone(),
        guest_path: project.path.clone(),
    }];

    let run = match sandbox_exec(backend, run_cmd).await {
        Ok(r) => r,
        Err(err) => {
            return Ok(infrastructure_error(
                backend,
                Some(project.path.clone()),
                format!("python run spawn: {err}"),
            ));
        }
    };

    Ok(classify_run_result(&run, backend, &project.path, opts))
}

pub(in crate::verify) async fn scaffold_python_project(
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
        _tempdir: tempdir,
    })
}

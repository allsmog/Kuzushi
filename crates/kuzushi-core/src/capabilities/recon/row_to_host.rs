use super::*;

pub(crate) fn row_to_host(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReconHost> {
    Ok(ReconHost {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        address: row.get(2)?,
        hostname: row.get(3)?,
        state: row.get(4)?,
    })
}

pub(crate) fn row_to_service(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReconService> {
    let port: i64 = row.get(2)?;
    Ok(ReconService {
        id: row.get(0)?,
        host_id: row.get(1)?,
        port: port as u16,
        proto: row.get(3)?,
        name: row.get(4)?,
        banner: row.get(5)?,
        state: row.get(6)?,
    })
}

pub(crate) fn row_to_note(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReconNote> {
    let data_raw: String = row.get(5)?;
    Ok(ReconNote {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        host_id: row.get(2)?,
        service_id: row.get(3)?,
        ntype: row.get(4)?,
        data: serde_json::from_str(&data_raw).unwrap_or(Value::Null),
    })
}

#[derive(Debug)]
pub(crate) struct ProcessOutput {
    pub(crate) stdout: Vec<u8>,
}

pub(crate) fn run_subprocess(
    tool_name: &str,
    binary: &str,
    args: &[String],
    cwd: Option<&Path>,
    cancel: &ScanCancellation,
    install_hint: &str,
) -> Result<ProcessOutput> {
    if cancel.is_cancelled() {
        anyhow::bail!("{tool_name} cancelled");
    }

    let mut command = Command::new(binary);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "{tool_name}: could not find subprocess binary {:?}. {install_hint}",
                binary
            )
        } else {
            anyhow::anyhow!("{tool_name}: could not start {:?}: {error}", binary)
        }
    })?;
    let process_group_id = child_process_group_id(&child);
    let stdout = child
        .stdout
        .take()
        .with_context(|| format!("Could not capture {tool_name} stdout"))?;
    let stderr = child
        .stderr
        .take()
        .with_context(|| format!("Could not capture {tool_name} stderr"))?;
    let stdout_reader = thread::spawn(move || read_pipe(stdout));
    let stderr_reader = thread::spawn(move || read_pipe(stderr));

    let status = wait_for_process(tool_name, &mut child, process_group_id, cancel)?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{tool_name} stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("{tool_name} stderr reader panicked"))??;

    let Some(status) = status else {
        anyhow::bail!("{tool_name} cancelled");
    };
    if !status.success() {
        let details = String::from_utf8_lossy(if stderr.is_empty() { &stdout } else { &stderr });
        anyhow::bail!(
            "{tool_name}: subprocess {:?} failed with status {}: {}",
            binary,
            status,
            details.trim()
        );
    }
    Ok(ProcessOutput { stdout })
}

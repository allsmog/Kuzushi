use crate::scan::ScanCancellation;
use anyhow::{Context, Result};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

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

    let mut child = spawn_subprocess(tool_name, binary, &mut command, install_hint)?;
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

    validate_subprocess_exit(tool_name, binary, status, stdout, stderr)
}

fn spawn_subprocess(
    tool_name: &str,
    binary: &str,
    command: &mut Command,
    install_hint: &str,
) -> Result<Child> {
    command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "{tool_name}: could not find subprocess binary {:?}. {install_hint}",
                binary
            )
        } else {
            anyhow::anyhow!("{tool_name}: could not start {:?}: {error}", binary)
        }
    })
}

fn validate_subprocess_exit(
    tool_name: &str,
    binary: &str,
    status: Option<ExitStatus>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> Result<ProcessOutput> {
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

fn wait_for_process(
    tool_name: &str,
    child: &mut Child,
    process_group_id: Option<u32>,
    cancel: &ScanCancellation,
) -> Result<Option<ExitStatus>> {
    loop {
        if cancel.is_cancelled() {
            kill_child(child, process_group_id);
            let _ = child.wait();
            return Ok(None);
        }
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("{tool_name}: could not poll subprocess"))?
        {
            return Ok(Some(status));
        }
        thread::sleep(Duration::from_millis(75));
    }
}

fn kill_child(child: &mut Child, process_group_id: Option<u32>) {
    #[cfg(unix)]
    {
        if let Some(process_group_id) = process_group_id {
            unsafe {
                libc::killpg(process_group_id as libc::pid_t, libc::SIGKILL);
            }
            return;
        }
    }
    let _ = child.kill();
}

fn child_process_group_id(child: &Child) -> Option<u32> {
    #[cfg(unix)]
    {
        Some(child.id())
    }

    #[cfg(not(unix))]
    {
        let _ = child;
        None
    }
}

fn read_pipe(mut pipe: impl Read) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    pipe.read_to_end(&mut buffer)?;
    Ok(buffer)
}

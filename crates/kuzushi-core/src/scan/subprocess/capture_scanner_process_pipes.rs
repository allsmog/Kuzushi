use super::*;

pub(in crate::scan) struct ScannerProcessReaders {
    stdout: thread::JoinHandle<Result<Vec<u8>>>,
    stderr: thread::JoinHandle<Result<Vec<u8>>>,
}

pub(in crate::scan) struct ScannerProcessOutput {
    pub(in crate::scan) stdout: Vec<u8>,
    pub(in crate::scan) stderr: Vec<u8>,
}

pub(in crate::scan) fn capture_scanner_process_pipes(
    child: &mut Child,
    scanner_name: &str,
) -> Result<ScannerProcessReaders> {
    let stdout = child
        .stdout
        .take()
        .with_context(|| format!("Could not capture {scanner_name} stdout"))?;
    let stderr = child
        .stderr
        .take()
        .with_context(|| format!("Could not capture {scanner_name} stderr"))?;

    Ok(ScannerProcessReaders {
        stdout: thread::spawn(move || {
            crate::bounded_subprocess::drain_bounded(
                stdout,
                crate::bounded_subprocess::DEFAULT_STDOUT_LIMIT,
                "scanner stdout",
            )
        }),
        stderr: thread::spawn(move || {
            crate::bounded_subprocess::drain_bounded(
                stderr,
                crate::bounded_subprocess::DEFAULT_STDERR_LIMIT,
                "scanner stderr",
            )
        }),
    })
}

pub(in crate::scan) fn wait_for_scanner_process(
    child: &RegisteredChild,
    cancel: &ScanCancellation,
) -> Result<Option<ExitStatus>> {
    loop {
        if cancel.is_cancelled() {
            child.kill_and_wait()?;
            return Ok(None);
        }

        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        thread::sleep(Duration::from_millis(75));
    }
}

pub(in crate::scan) fn join_scanner_process_readers(
    readers: ScannerProcessReaders,
    scanner_name: &str,
) -> Result<ScannerProcessOutput> {
    let stdout = readers
        .stdout
        .join()
        .map_err(|_| anyhow::anyhow!("{scanner_name} stdout reader panicked"))??;
    let stderr = readers
        .stderr
        .join()
        .map_err(|_| anyhow::anyhow!("{scanner_name} stderr reader panicked"))??;

    Ok(ScannerProcessOutput { stdout, stderr })
}

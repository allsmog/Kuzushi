use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ExitStatus, Output};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

type ControlledReader = JoinHandle<Result<Vec<u8>>>;
type ControlledWriter = JoinHandle<Result<()>>;
type ControlledFailure = Arc<Mutex<Option<String>>>;

pub(super) struct ControlledIo {
    stdout: ControlledReader,
    stderr: ControlledReader,
    stdin: Option<ControlledWriter>,
    failure: ControlledFailure,
}

impl ControlledIo {
    pub(super) fn capture(
        child: &mut Child,
        input: Option<Vec<u8>>,
        label: &str,
        stdout_file: Option<(std::fs::File, u64)>,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> Result<Self> {
        let stdout = child
            .stdout
            .take()
            .with_context(|| format!("Could not capture {label} stdout"))?;
        let stderr = child
            .stderr
            .take()
            .with_context(|| format!("Could not capture {label} stderr"))?;
        let stdin = input
            .map(|input| controlled_stdin(child, label).map(|stdin| (stdin, input)))
            .transpose()?;
        let failure = Arc::new(Mutex::new(None));
        let stdout = match stdout_file {
            Some((file, limit)) => {
                spawn_controlled_file_reader(stdout, file, limit, Arc::clone(&failure))
            }
            None => spawn_controlled_reader(stdout, stdout_limit, "stdout", Arc::clone(&failure)),
        };
        let stderr = spawn_controlled_reader(stderr, stderr_limit, "stderr", Arc::clone(&failure));
        let stdin =
            stdin.map(|(stdin, input)| spawn_controlled_writer(stdin, input, Arc::clone(&failure)));
        Ok(Self {
            stdout,
            stderr,
            stdin,
            failure,
        })
    }

    pub(super) fn failure(&self) -> Result<Option<String>> {
        self.failure
            .lock()
            .map(|slot| slot.clone())
            .map_err(|_| anyhow::anyhow!("subprocess output failure state was poisoned"))
    }

    pub(super) fn join(self, status: ExitStatus, label: &str) -> Result<Output> {
        let stdout = join_controlled_reader(self.stdout, label, "stdout");
        let stderr = join_controlled_reader(self.stderr, label, "stderr");
        let stdin = if let Some(stdin) = self.stdin {
            stdin
                .join()
                .map_err(|_| anyhow::anyhow!("{label} stdin writer panicked"))?
        } else {
            Ok(())
        };
        let stdout = stdout?;
        let stderr = stderr?;
        stdin?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    pub(super) fn join_cleanup(self, error: anyhow::Error) -> anyhow::Error {
        let stdout = join_controlled_reader(self.stdout, "subprocess", "stdout");
        let stderr = join_controlled_reader(self.stderr, "subprocess", "stderr");
        let stdin = self.stdin.map(|writer| {
            writer
                .join()
                .map_err(|_| anyhow::anyhow!("subprocess stdin writer panicked"))?
        });
        [
            stdout.map(|_| ()),
            stderr.map(|_| ()),
            stdin.unwrap_or(Ok(())),
        ]
        .into_iter()
        .filter_map(Result::err)
        .fold(error, |primary, cleanup| cleanup.context(primary))
    }
}

fn controlled_stdin(child: &mut Child, label: &str) -> Result<ChildStdin> {
    child
        .stdin
        .take()
        .with_context(|| format!("Could not capture {label} stdin"))
}

fn spawn_controlled_reader<R: Read + Send + 'static>(
    reader: R,
    limit: usize,
    stream: &'static str,
    failure: ControlledFailure,
) -> ControlledReader {
    thread::spawn(move || match read_controlled_pipe(reader, limit, stream) {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            record_controlled_failure(&failure, &error);
            Err(error)
        }
    })
}

fn spawn_controlled_file_reader<R: Read + Send + 'static>(
    reader: R,
    file: std::fs::File,
    limit: u64,
    failure: ControlledFailure,
) -> ControlledReader {
    thread::spawn(move || match copy_controlled_pipe(reader, file, limit) {
        Ok(()) => Ok(Vec::new()),
        Err(error) => {
            record_controlled_failure(&failure, &error);
            Err(error)
        }
    })
}

fn copy_controlled_pipe(mut reader: impl Read, mut file: std::fs::File, limit: u64) -> Result<()> {
    let mut written = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            file.flush()?;
            return Ok(());
        }
        let remaining = limit.saturating_sub(written);
        let accepted = count.min(usize::try_from(remaining).unwrap_or(usize::MAX));
        file.write_all(&buffer[..accepted])?;
        written += accepted as u64;
        anyhow::ensure!(
            accepted == count,
            "subprocess stdout exceeded the {limit}-byte file limit"
        );
    }
}

fn read_controlled_pipe(mut reader: impl Read, limit: usize, stream: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    reader
        .by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= limit,
        "subprocess {stream} exceeded the {limit}-byte capture limit"
    );
    Ok(bytes)
}

fn spawn_controlled_writer(
    mut stdin: ChildStdin,
    input: Vec<u8>,
    failure: ControlledFailure,
) -> ControlledWriter {
    thread::spawn(move || {
        let result = stdin.write_all(&input).map_err(anyhow::Error::from);
        drop(stdin);
        if let Err(error) = &result {
            record_controlled_failure(&failure, error);
        }
        result
    })
}

fn record_controlled_failure(failure: &ControlledFailure, error: &anyhow::Error) {
    if let Ok(mut slot) = failure.lock() {
        if slot.is_none() {
            *slot = Some(error.to_string());
        }
    }
}

fn join_controlled_reader(reader: ControlledReader, label: &str, stream: &str) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("{label} {stream} reader panicked"))?
}

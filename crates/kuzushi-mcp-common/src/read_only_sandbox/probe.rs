use super::backend::{build_command, detect_backend};
use super::{resolve_regular_executable, ReadOnlySandboxBackend};
use crate::process::{run_bounded_process, ProcessLimits};
use crate::AuthorizedDirectory;
use anyhow::Result;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

const SELF_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) async fn self_probe_candidate() -> Option<ReadOnlySandboxBackend> {
    let backend = detect_backend()?;
    self_probe(backend).await.then_some(backend)
}

async fn self_probe(backend: ReadOnlySandboxBackend) -> bool {
    let fixture = match SandboxProbeFixture::new() {
        Ok(fixture) => fixture,
        Err(_) => return false,
    };
    let shell = match resolve_regular_executable(OsStr::new("/bin/sh")) {
        Ok(shell) => shell,
        Err(_) => return false,
    };
    let args = fixture.arguments();
    let input = match fixture.input.try_clone() {
        Ok(input) => input,
        Err(_) => return false,
    };
    let mut sandboxed = match build_command(backend, &shell, args, input) {
        Ok(command) => command,
        Err(_) => return false,
    };
    let command = match sandboxed.command_mut() {
        Ok(command) => command,
        Err(_) => return false,
    };
    let passed = run_bounded_process(command, "MCP sandbox self-probe", probe_limits())
        .await
        .is_ok_and(|output| output.status.success());
    drop(fixture);
    passed
}

struct SandboxProbeFixture {
    input: AuthorizedDirectory,
    root_path: PathBuf,
    denied_path: PathBuf,
    listener: std::net::TcpListener,
    _outer: TempDir,
}

impl SandboxProbeFixture {
    fn new() -> Result<Self> {
        let outer = tempfile::Builder::new()
            .prefix("kuzushi-sandbox-probe-")
            .tempdir()?;
        let outer_path = std::fs::canonicalize(outer.path())?;
        let root_path = outer_path.join("allowed");
        std::fs::create_dir(&root_path)?;
        std::fs::write(root_path.join("value"), b"allowed")?;
        let denied_path = outer_path.join("denied");
        std::fs::write(&denied_path, b"denied")?;
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let capability = crate::ReadRootCapability::new([root_path.clone()])?;
        let input = capability.authorize_directory(&root_path)?;
        Ok(Self {
            input,
            root_path,
            denied_path,
            listener,
            _outer: outer,
        })
    }

    fn arguments(&self) -> Vec<OsString> {
        vec![
            OsString::from("-c"),
            OsString::from(
                "test \"$(cat \"$1/value\")\" = allowed \
                 && ! cat \"$2\" >/dev/null 2>&1 \
                 && ! (printf denied > \"$1/forbidden-write\") 2>/dev/null \
                 && printf scratch > \"$TMPDIR/probe-write\" \
                 && test \"$(cat \"$TMPDIR/probe-write\")\" = scratch \
                 && if command -v nc >/dev/null 2>&1; then ! nc -z 127.0.0.1 \"$3\"; else true; fi",
            ),
            OsString::from("sandbox-probe"),
            self.root_path.as_os_str().to_owned(),
            self.denied_path.as_os_str().to_owned(),
            OsString::from(
                self.listener
                    .local_addr()
                    .expect("probe listener address")
                    .port()
                    .to_string(),
            ),
        ]
    }
}

fn probe_limits() -> ProcessLimits {
    ProcessLimits {
        timeout: SELF_PROBE_TIMEOUT,
        stdout_bytes: 8 * 1024,
        stderr_bytes: 8 * 1024,
    }
}

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

#[derive(Debug, Clone)]
pub(crate) struct UnsupportedAdvisory {
    pub(crate) method: String,
    pub(crate) reason: String,
    pub(crate) workaround: String,
}

impl UnsupportedAdvisory {
    pub(crate) fn to_tool_result(&self) -> Value {
        json!({
            "unsupported": true,
            "method": self.method,
            "reason": self.reason,
            "workaround": self.workaround,
        })
    }
}

/// A line-delimited JSON-RPC 2.0 client for the `kuzushi-mcp-clang`
/// stdio server. The server's protocol is implemented in
/// `kuzushi_mcp_common::server::serve_stdio` and accepts `initialize`,
/// `tools/list`, and `tools/call` methods.
///
/// We keep the subprocess alive for the duration of a `uaf-hunt:hunt`
/// run so clangd's index isn't rebuilt between calls. The client is
/// not thread-safe; only one tool call may be in flight at a time
/// (matching how the tool-loop driver invokes it sequentially).
pub(crate) struct ClangMcpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl ClangMcpClient {
    /// Spawn `kuzushi-mcp-clang` with an explicit, canonical read capability.
    pub(crate) fn spawn(repo_root: &Path, _compile_commands_path: &Path) -> Result<Self> {
        let binary = locate_mcp_clang_binary()?;
        let mut child = mcp_clang_command(&binary, repo_root)?
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "uaf-hunt: could not spawn mcp-clang at {} \
                     (is `kuzushi-mcp-clang` in the same directory as `kuzushi` or on PATH?)",
                    binary.display()
                )
            })?;
        let stdin = child
            .stdin
            .take()
            .context("uaf-hunt: mcp-clang spawned without a writable stdin pipe")?;
        let stdout = BufReader::new(
            child
                .stdout
                .take()
                .context("uaf-hunt: mcp-clang spawned without a readable stdout pipe")?,
        );
        let mut client = Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        client.handshake().context(
            "uaf-hunt: mcp-clang initialize handshake failed; check that clangd is on PATH and \
             that the compile_commands.json path is valid",
        )?;
        Ok(client)
    }

    fn handshake(&mut self) -> Result<()> {
        let _ = self.request(
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "kuzushi-uaf-hunt", "version": "0"},
                "capabilities": {},
            }),
        )?;
        Ok(())
    }

    /// Call an mcp-clang tool by name (e.g. `clang.callers`). The
    /// `arguments` object is forwarded verbatim. Returns the parsed
    /// `structuredContent` (or the text content if structured is
    /// missing). Caller is responsible for serialising the result back
    /// to the LLM as JSON text.
    pub(crate) fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value> {
        let response = self
            .request("tools/call", json!({"name": name, "arguments": arguments}))
            .with_context(|| format!("uaf-hunt: mcp-clang tools/call {name} failed"))?;
        if response.get("isError").and_then(Value::as_bool) == Some(true) {
            let detail = response
                .get("content")
                .and_then(|content| content.as_array())
                .and_then(|items| items.first())
                .and_then(|first| first.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("(no error detail)");
            anyhow::bail!("uaf-hunt: mcp-clang tool {name} returned error: {detail}");
        }
        Ok(response
            .get("structuredContent")
            .cloned()
            .or_else(|| response.get("content").cloned())
            .unwrap_or(Value::Null))
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let mut line = serde_json::to_string(&request).context("uaf-hunt: encode JSON-RPC")?;
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .context("uaf-hunt: mcp-clang stdin write failed")?;
        self.stdin
            .flush()
            .context("uaf-hunt: mcp-clang stdin flush failed")?;
        let response = self
            .read_response_with_id(id)
            .with_context(|| format!("uaf-hunt: reading mcp-clang response for {method}"))?;
        if let Some(error) = response.get("error") {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("(no message)");
            anyhow::bail!("uaf-hunt: mcp-clang returned JSON-RPC error code {code}: {message}");
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }

    fn read_response_with_id(&mut self, expected_id: u64) -> Result<Value> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .stdout
                .read_line(&mut line)
                .context("uaf-hunt: stdout read failed")?;
            if n == 0 {
                anyhow::bail!("uaf-hunt: mcp-clang closed stdout unexpectedly");
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let response: Value = serde_json::from_str(trimmed)
                .with_context(|| format!("uaf-hunt: mcp-clang sent non-JSON line: {trimmed}"))?;
            // The mcp server may surface a `notifications/...` reply
            // we don't care about; skip anything not matching our id.
            let id_matches = response
                .get("id")
                .and_then(Value::as_u64)
                .is_some_and(|id| id == expected_id);
            if id_matches {
                return Ok(response);
            }
        }
    }
}

fn mcp_clang_command(binary: &Path, repo_root: &Path) -> Result<Command> {
    let canonical_root = std::fs::canonicalize(repo_root).with_context(|| {
        format!(
            "uaf-hunt: could not canonicalize mcp-clang read root {}",
            repo_root.display()
        )
    })?;
    anyhow::ensure!(
        canonical_root.is_dir(),
        "uaf-hunt: mcp-clang read root is not a directory: {}",
        canonical_root.display()
    );
    let read_roots = serde_json::to_string(&[&canonical_root])
        .context("uaf-hunt: encode mcp-clang read capability")?;
    let path = std::env::var_os("PATH").context("uaf-hunt: PATH is required to locate clangd")?;
    let mut command = Command::new(binary);
    command
        .current_dir(&canonical_root)
        .env_clear()
        .env("PATH", path)
        .env(kuzushi_mcp_common::MCP_READ_ROOTS_ENV, read_roots);
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    Ok(command)
}

impl Drop for ClangMcpClient {
    fn drop(&mut self) {
        // Best-effort: send a shutdown so clangd exits cleanly, then
        // kill the subprocess. We don't propagate errors here — by the
        // time `drop` runs the hunt is finishing one way or another.
        let _ = writeln!(
            self.stdin,
            r#"{{"jsonrpc":"2.0","id":999,"method":"shutdown","params":null}}"#
        );
        let _ = self.stdin.flush();
        // Give the server a half-second to exit on its own before
        // we send SIGKILL.
        std::thread::sleep(Duration::from_millis(500));
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Find `kuzushi-mcp-clang` in three places, in order:
/// 1. Sibling of the running `kuzushi` binary (same `target/release`
///    or `target/debug` dir). This is the common case in development.
/// 2. `KUZUSHI_MCP_CLANG_BIN` env var (operator override).
/// 3. `kuzushi-mcp-clang` on `$PATH`.
///
/// Bails loudly if none of those resolve — silently degrading to a
/// no-clang mode would defeat the entire point of this module.
pub(crate) fn locate_mcp_clang_binary() -> Result<PathBuf> {
    explicit_mcp_clang_binary()?
        .or_else(sibling_mcp_clang_binary)
        .or_else(which_kuzushi_mcp_clang)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "uaf-hunt: could not find kuzushi-mcp-clang. Build it with \
         `cargo build -p kuzushi-mcp-clang --release` (it will land \
         next to the `kuzushi` binary) or set KUZUSHI_MCP_CLANG_BIN \
         to an absolute path."
            )
        })
}

fn explicit_mcp_clang_binary() -> Result<Option<PathBuf>> {
    let Some(explicit) = std::env::var_os("KUZUSHI_MCP_CLANG_BIN") else {
        return Ok(None);
    };
    let path = PathBuf::from(explicit);
    if path.exists() {
        return Ok(Some(path));
    }
    anyhow::bail!(
        "uaf-hunt: KUZUSHI_MCP_CLANG_BIN points at {}, which does not exist",
        path.display()
    )
}

fn sibling_mcp_clang_binary() -> Option<PathBuf> {
    let current_exe = std::env::current_exe().ok()?;
    let sibling = current_exe.parent()?.join("kuzushi-mcp-clang");
    sibling.exists().then_some(sibling)
}

fn which_kuzushi_mcp_clang() -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("kuzushi-mcp-clang");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Re-shape an error from `ClangMcpClient::call_tool` into an
/// `UnsupportedAdvisory` when it looks like an LSP "method not found"
/// (JSON-RPC error code -32601). The toolbox handler then returns the
/// advisory to the agent as a successful tool result so the agent sees
/// a concrete workaround instead of a cryptic error and a wasted step.
///
/// Returns `None` for any error that isn't an unsupported-method error
/// — the handler bubbles those up the normal `firstClangError` path.
pub(crate) fn rewrite_unsupported_method_error(
    clang_method: &str,
    error: &anyhow::Error,
) -> Option<UnsupportedAdvisory> {
    let chain = format!("{error:#}");
    let looks_unsupported = chain.contains("method not found") || chain.contains("-32601");
    if !looks_unsupported {
        return None;
    }
    let advisory = match clang_method {
        "clang.callees" => UnsupportedAdvisory {
            method: clang_method.to_string(),
            reason: "clangd `callHierarchy/outgoingCalls` is unimplemented in this clangd \
                     build (typical for clangd 18 and earlier)."
                .to_string(),
            workaround: "Use `clang_definition` to jump to the function body, then `read_file` \
                         on that range and identify call sites by reading the body. Or use \
                         `grep` for specific callee names to confirm individual edges."
                .to_string(),
        },
        other => UnsupportedAdvisory {
            method: other.to_string(),
            reason: "clangd reports this method as unimplemented.".to_string(),
            workaround: "Substitute a structural pass: `grep` plus `read_file` and \
                         `clang_definition`."
                .to_string(),
        },
    };
    Some(advisory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn restore_env(name: &str, previous: Option<std::ffi::OsString>) {
        match previous {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }

    #[test]
    fn locate_mcp_clang_honors_explicit_path_and_reports_missing_override() {
        let _guard = env_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("kuzushi-mcp-clang");
        std::fs::write(&binary, "").unwrap();

        let previous = std::env::var_os("KUZUSHI_MCP_CLANG_BIN");
        std::env::set_var("KUZUSHI_MCP_CLANG_BIN", &binary);
        assert_eq!(locate_mcp_clang_binary().unwrap(), binary);

        std::env::set_var("KUZUSHI_MCP_CLANG_BIN", temp.path().join("missing"));
        let err = locate_mcp_clang_binary().unwrap_err().to_string();
        restore_env("KUZUSHI_MCP_CLANG_BIN", previous);

        assert!(err.contains("KUZUSHI_MCP_CLANG_BIN"));
        assert!(err.contains("does not exist"));
    }

    #[test]
    #[cfg(unix)]
    fn which_mcp_clang_finds_binary_on_path() {
        let _guard = env_lock().lock().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("kuzushi-mcp-clang");
        std::fs::write(&binary, "").unwrap();

        let previous = std::env::var_os("PATH");
        std::env::set_var("PATH", temp.path());
        assert_eq!(which_kuzushi_mcp_clang(), Some(binary));
        restore_env("PATH", previous);
    }

    #[test]
    fn mcp_clang_command_grants_only_the_canonical_target_read_root() {
        let root = tempfile::tempdir().unwrap();
        let command = mcp_clang_command(Path::new("/bin/true"), root.path()).unwrap();
        let expected_root = std::fs::canonicalize(root.path()).unwrap();
        let env = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();

        assert_eq!(command.get_current_dir(), Some(expected_root.as_path()));
        assert_eq!(
            env.get(kuzushi_mcp_common::MCP_READ_ROOTS_ENV),
            Some(&Some(serde_json::to_string(&[expected_root]).unwrap()))
        );
        assert!(env.contains_key("PATH"));
        assert!(!env.contains_key("KUZUSHI_MCP_WRITE_ROOTS"));
        assert!(!env.contains_key("KUZUSHI_COMPILE_COMMANDS_PATH"));
        #[cfg(not(windows))]
        assert_eq!(env.len(), 2);
    }

    #[test]
    fn mcp_clang_command_fails_closed_for_a_missing_read_root() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");

        let error = mcp_clang_command(Path::new("/bin/true"), &missing).unwrap_err();

        assert!(error.to_string().contains("could not canonicalize"));
    }
}

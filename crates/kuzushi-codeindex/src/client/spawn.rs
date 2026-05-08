use super::prelude::*;
use super::*;

impl McpClient {
    /// Spawn a server binary by name. Caller is responsible for ensuring
    /// the binary is on PATH; otherwise this errors.
    pub async fn spawn(binary: &str) -> Result<Self> {
        let mut child = Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("could not spawn MCP server `{binary}`"))?;
        let stdin = child.stdin.take().context("server stdin missing")?;
        let stdout = child.stdout.take().context("server stdout missing")?;
        Ok(Self {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            next_id: AtomicI64::new(1),
            initialized: Mutex::new(false),
            binary: binary.to_string(),
        })
    }

    /// Send `initialize` if we haven't already.
    pub async fn ensure_initialized(&self) -> Result<()> {
        let mut init = self.initialized.lock().await;
        self.ensure_initialized_state(&mut init).await
    }

    pub(crate) async fn ensure_initialized_state(&self, init: &mut bool) -> Result<()> {
        if *init {
            return Ok(());
        }
        self.send_initialize().await?;
        *init = true;
        Ok(())
    }

    pub(crate) async fn send_initialize(&self) -> Result<()> {
        let _ = self.request("initialize", json!({})).await?;
        self.notify("notifications/initialized", json!({})).await
    }

    /// Call a tool by name. The MCP server returns a `content` array plus
    /// a `structuredContent` mirror; we prefer the latter when present.
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
        self.ensure_initialized().await?;
        let resp = self
            .request("tools/call", tool_call_params(name, arguments))
            .await?;
        tool_call_result(&self.binary, resp)
    }

    pub async fn shutdown(&self) -> Result<()> {
        let _ = self.notify("shutdown", json!({})).await;
        let _ = self.notify("exit", json!({})).await;
        let mut child = self.child.lock().await;
        let _ = child.kill().await;
        Ok(())
    }

    pub(crate) async fn request(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.write_line(&json_rpc_request_body(id, method, params))
            .await?;
        self.read_response_for_id(id).await
    }

    pub(crate) async fn read_response_for_id(&self, id: i64) -> Result<Value> {
        loop {
            if let Some(result) = self.read_response_candidate(id).await? {
                return Ok(result);
            }
            // Notifications and responses to other ids are ignored; we
            // serialise calls so this should be rare in practice.
        }
    }

    pub(crate) async fn read_response_candidate(&self, id: i64) -> Result<Option<Value>> {
        let resp = self.read_line().await?;
        response_result_for_id(&self.binary, &resp, id)
    }

    pub(crate) async fn notify(&self, method: &str, params: Value) -> Result<()> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.write_line(&body).await
    }

    pub(crate) async fn write_line(&self, body: &Value) -> Result<()> {
        let raw = json_line(body)?;
        let mut stdin = self.stdin.lock().await;
        write_json_line(&mut stdin, &raw).await
    }

    pub(crate) async fn read_line(&self) -> Result<Value> {
        let line = self.read_raw_line().await?;
        parse_json_line(&line)
    }

    pub(crate) async fn read_raw_line(&self) -> Result<String> {
        let mut stdout = self.stdout.lock().await;
        let mut line = String::new();
        let n = stdout.read_line(&mut line).await?;
        ensure_server_line_read(n)?;
        Ok(line)
    }
}

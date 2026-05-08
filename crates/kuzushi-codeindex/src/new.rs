use super::prelude::*;
use super::*;

impl IndexFacade {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a facade that auto-spawns each backend it can find on PATH.
    /// Backends whose binaries are missing are simply omitted from the
    /// routing table — every query degrades gracefully to whatever
    /// remains.
    pub async fn with_available_backends() -> Self {
        let mut facade = Self::new();
        if let Ok(client) = McpClient::spawn(Backend::Gtags.binary_name()).await {
            facade.gtags = Some(client);
        }
        if let Ok(client) = McpClient::spawn(Backend::Clang.binary_name()).await {
            facade.clang = Some(client);
        }
        if let Ok(client) = McpClient::spawn(Backend::Joern.binary_name()).await {
            facade.joern = Some(client);
        }
        facade
    }

    /// Returns which backends are live for this facade.
    pub fn live_backends(&self) -> Vec<Backend> {
        let mut out = Vec::new();
        if self.gtags.is_some() {
            out.push(Backend::Gtags);
        }
        if self.clang.is_some() {
            out.push(Backend::Clang);
        }
        if self.joern.is_some() {
            out.push(Backend::Joern);
        }
        out
    }

    /// Find symbol definitions. Routes per [`RoutingTable`].
    pub async fn definitions(&mut self, symbol: &str, repo: &Path) -> Result<Vec<Symbol>> {
        let value = self
            .first_successful_backend(Query::Definitions, "definitions", symbol, |backend| {
                definition_call(backend, symbol, repo)
            })
            .await?;
        Ok(symbol_matches(&value))
    }

    /// Find symbol references (callers, usages). Routes per
    /// [`RoutingTable`].
    pub async fn references(&mut self, symbol: &str, repo: &Path) -> Result<Vec<Symbol>> {
        let value = self
            .first_successful_backend(Query::References, "references", symbol, |backend| {
                references_call(backend, symbol, repo)
            })
            .await?;
        Ok(symbol_matches(&value))
    }

    /// Methods that call the named function. Routes per [`RoutingTable`].
    /// Tries clang first when (file, line, column) is supplied; otherwise
    /// falls through to joern's name-based query.
    pub async fn callers_of(
        &mut self,
        symbol: &str,
        position: Option<&FilePosition>,
    ) -> Result<Value> {
        self.first_successful_backend(Query::CallersOfFunction, "callers_of", symbol, |backend| {
            callers_call(backend, symbol, position)
        })
        .await
    }

    /// Methods called by the named function. Routes per [`RoutingTable`].
    pub async fn callees_of(
        &mut self,
        symbol: &str,
        position: Option<&FilePosition>,
    ) -> Result<Value> {
        self.first_successful_backend(Query::CalleesOfFunction, "callees_of", symbol, |backend| {
            callees_call(backend, symbol, position)
        })
        .await
    }

    /// Taint paths from a source pattern to a sink pattern. joern only;
    /// no fallback because gtags and clang lack the dataflow primitives.
    pub async fn taint_paths(
        &mut self,
        source: &str,
        sink: &str,
        max_paths: Option<usize>,
    ) -> Result<Value> {
        let Some(client) = self.client_mut(Backend::Joern) else {
            anyhow::bail!(
                "BackendUnavailable: taint_paths requires joern; install via https://docs.joern.io/installation"
            );
        };
        let mut args = serde_json::json!({
            "source": source,
            "sink": sink,
        });
        if let Some(n) = max_paths {
            args["maxPaths"] = serde_json::json!(n);
        }
        client.call_tool("joern.taint_paths", args).await
    }

    /// Locate `unsafe { ... }` regions, optionally constrained to a file.
    /// joern Rust frontend.
    pub async fn unsafe_blocks(&mut self, file: Option<&str>) -> Result<Value> {
        let Some(client) = self.client_mut(Backend::Joern) else {
            anyhow::bail!(
                "BackendUnavailable: unsafe_blocks requires joern; install via https://docs.joern.io/installation"
            );
        };
        let mut args = serde_json::json!({});
        if let Some(f) = file {
            args["file"] = serde_json::json!(f);
        }
        client.call_tool("joern.unsafe_blocks", args).await
    }

    /// Locate FFI boundaries (extern, JNI, dlsym/dlopen). joern only.
    pub async fn ffi_boundaries(&mut self) -> Result<Value> {
        let Some(client) = self.client_mut(Backend::Joern) else {
            anyhow::bail!(
                "BackendUnavailable: ffi_boundaries requires joern; install via https://docs.joern.io/installation"
            );
        };
        client
            .call_tool("joern.ffi_boundaries", serde_json::json!({}))
            .await
    }

    /// Type information at a position. clang only — needs type-and-macro
    /// awareness from clangd.
    pub async fn type_at(&mut self, position: &FilePosition) -> Result<Value> {
        let Some(client) = self.client_mut(Backend::Clang) else {
            anyhow::bail!(
                "BackendUnavailable: type_at requires clangd; install LLVM (`apt install clangd` / `brew install llvm`)"
            );
        };
        client
            .call_tool(
                "clang.type_at",
                serde_json::json!({
                    "repoPath": position.repo,
                    "file": position.file,
                    "line": position.line,
                    "column": position.column,
                }),
            )
            .await
    }

    /// AST subtree at a position via clangd's `textDocument/ast` extension.
    pub async fn ast(&mut self, position: &FilePosition) -> Result<Value> {
        let Some(client) = self.client_mut(Backend::Clang) else {
            anyhow::bail!(
                "BackendUnavailable: ast requires clangd; install LLVM (`apt install clangd` / `brew install llvm`)"
            );
        };
        client
            .call_tool(
                "clang.ast",
                serde_json::json!({
                    "repoPath": position.repo,
                    "file": position.file,
                    "line": position.line,
                    "column": position.column,
                }),
            )
            .await
    }

    pub(crate) fn client_mut(&mut self, backend: Backend) -> Option<&mut McpClient> {
        match backend {
            Backend::Gtags => self.gtags.as_mut(),
            Backend::Clang => self.clang.as_mut(),
            Backend::Joern => self.joern.as_mut(),
        }
    }

    pub(crate) async fn first_successful_backend<F>(
        &mut self,
        query: Query,
        operation: &str,
        symbol: &str,
        mut build_call: F,
    ) -> Result<Value>
    where
        F: FnMut(Backend) -> Option<BackendToolCall>,
    {
        for backend in self.routing.order_for(query) {
            let Some(call) = build_call(backend) else {
                continue;
            };
            let Some(client) = self.client_mut(backend) else {
                continue;
            };
            match client.call_tool(call.tool, call.args).await {
                Ok(value) => return Ok(value),
                Err(err) => log_backend_failure(backend, operation, symbol, &err),
            }
        }
        anyhow::bail!("no backend was able to answer {operation}({symbol})")
    }
}

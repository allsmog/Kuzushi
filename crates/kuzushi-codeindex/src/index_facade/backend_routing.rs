use super::*;

impl IndexFacade {
    pub(crate) fn client_mut(&mut self, backend: Backend) -> Option<&mut McpClient> {
        match backend {
            Backend::Gtags => self.gtags.as_mut(),
            Backend::Clang => self.clang.as_mut(),
            Backend::Cpg => self.cpg.as_mut(),
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
                Err(err) => self.diagnostics.push(backend_failure_diagnostic(
                    backend, operation, symbol, &err,
                )),
            }
        }
        anyhow::bail!("no backend was able to answer {operation}({symbol})")
    }
}

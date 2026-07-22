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
        if let Ok(client) = McpClient::spawn(Backend::Cpg.binary_name()).await {
            facade.cpg = Some(client);
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
        if self.cpg.is_some() {
            out.push(Backend::Cpg);
        }
        out
    }

    /// Drain recoverable backend failures without writing to the host
    /// terminal. Embedders choose the appropriate presentation boundary.
    pub fn take_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.diagnostics)
    }
}

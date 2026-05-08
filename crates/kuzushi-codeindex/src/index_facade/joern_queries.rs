use super::*;

impl IndexFacade {
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
}

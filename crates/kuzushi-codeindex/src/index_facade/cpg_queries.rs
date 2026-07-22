use super::*;

impl IndexFacade {
    /// Taint paths from a source pattern to a sink pattern. cpg-rs only;
    /// no fallback because gtags and clang lack the dataflow primitives.
    pub async fn taint_paths(
        &mut self,
        source: &str,
        sink: &str,
        max_paths: Option<usize>,
    ) -> Result<Value> {
        let Some(client) = self.client_mut(Backend::Cpg) else {
            anyhow::bail!(
                "BackendUnavailable: taint_paths requires the cpg backend (kuzushi-mcp-cpg on PATH)"
            );
        };
        let mut args = serde_json::json!({
            "source": source,
            "sink": sink,
        });
        if let Some(n) = max_paths {
            args["maxPaths"] = serde_json::json!(n);
        }
        client.call_tool("cpg.taint_paths", args).await
    }

    /// `unsafe { ... }` regions have no cpg-rs query yet. Refuse with the
    /// working alternative instead of faking an empty result.
    pub async fn unsafe_blocks(&mut self, _file: Option<&str>) -> Result<Value> {
        anyhow::bail!(
            "BackendUnavailable: unsafe_blocks has no cpg-rs equivalent; use \
             `tree_sitter:query` with an `(unsafe_block) @u` pattern on the Rust grammar"
        );
    }

    /// FFI boundary enumeration is PARTIAL on cpg-rs: dynamic-load call
    /// sites resolve through `cpg.callers_of` (dlopen/dlsym/JNI_*), but
    /// `extern \"C\"` declarations are not modeled. Refuse with guidance
    /// rather than returning a silently incomplete inventory.
    pub async fn ffi_boundaries(&mut self) -> Result<Value> {
        anyhow::bail!(
            "BackendUnavailable: ffi_boundaries is only partially covered by cpg-rs; \
             query `cpg.callers_of` for dlopen/dlsym/JNI_* call sites (extern decls \
             are not modeled)"
        );
    }
}

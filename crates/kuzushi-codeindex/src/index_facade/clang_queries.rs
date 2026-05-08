use super::*;

impl IndexFacade {
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
}

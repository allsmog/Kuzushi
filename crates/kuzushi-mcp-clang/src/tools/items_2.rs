use super::prelude::*;
use super::*;

#[allow(dead_code)]
pub(crate) fn stub_descriptor(name: &'static str, desc: &'static str) -> Tool {
    Tool {
        name: name.into(),
        description: desc.into(),
        input_schema: json!({"type": "object"}),
    }
}

pub(crate) struct HealthTool;

pub(crate) struct CompileCommandsTool;

pub(crate) struct DefinitionTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct ReferencesTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct TypeAtTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct AstTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct CallersTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct CalleesTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct MacroExpandTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct SemanticTokensTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

pub(crate) struct DiagnosticsTool {
    pub(crate) handle: Arc<ClangdHandle>,
}

#[allow(dead_code)]
pub(crate) struct NotYetImplemented(pub(crate) &'static str);

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(serde_json::to_value(health_summary().await)?)
    }
}

pub(crate) fn ensure_clangd() -> Result<()> {
    if which("clangd").is_none() {
        anyhow::bail!(
            "BackendUnavailable: clangd not on PATH. Install LLVM (e.g. `apt install clangd` / `brew install llvm`)."
        );
    }
    Ok(())
}

pub(crate) fn require_str<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {name}"))
}

pub(crate) fn require_u32(args: &Value, name: &str) -> Result<u32> {
    args.get(name)
        .and_then(Value::as_u64)
        .map(|n| n as u32)
        .ok_or_else(|| anyhow::anyhow!("missing required integer argument: {name}"))
}

pub(crate) struct FileRequest {
    pub(crate) repo: PathBuf,
    pub(crate) file: PathBuf,
}

impl FileRequest {
    pub(crate) fn from_args(args: &Value) -> Result<Self> {
        let repo = PathBuf::from(require_str(args, "repoPath")?);
        let file = repo.join(require_str(args, "file")?);
        Ok(Self { repo, file })
    }

    pub(crate) async fn client(&self, handle: &ClangdHandle) -> Result<Arc<ClangdClient>> {
        handle.for_repo(&self.repo).await
    }

    pub(crate) fn text_document(&self) -> Value {
        json!({ "textDocument": { "uri": format!("file://{}", self.file.display()) } })
    }
}

pub(crate) struct PositionRequest {
    pub(crate) file: FileRequest,
    pub(crate) line: u32,
    pub(crate) column: u32,
}

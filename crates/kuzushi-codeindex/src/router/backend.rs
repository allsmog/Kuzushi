use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Gtags,
    Clang,
    Cpg,
}

impl Backend {
    pub fn binary_name(self) -> &'static str {
        match self {
            Self::Gtags => "kuzushi-mcp-gtags",
            Self::Clang => "kuzushi-mcp-clang",
            Self::Cpg => "kuzushi-mcp-cpg",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Query {
    Definitions,
    References,
    SymbolsInFile,
    FilesMatching,
    Completion,
    CallersOfFunction,
    CalleesOfFunction,
    TaintPaths,
    ReachingDef,
    UnsafeBlocks,
    FfiBoundaries,
    TypeAtPosition,
    AstAtPosition,
    MacroExpansion,
    MethodAtPosition,
}

#[derive(Debug, Clone, Copy)]
pub struct BackendCapability {
    pub query: Query,
    pub primary: Backend,
    pub fallback: Option<Backend>,
    pub last_resort: Option<Backend>,
}

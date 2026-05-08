use super::prelude::*;
use super::*;

pub const STATIC_REGISTRY_VERSION: &str = "2026-05-06.1";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StaticRegistryKind {
    Source,
    Sink,
    Sanitizer,
    Guard,
}

impl StaticRegistryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Sink => "sink",
            Self::Sanitizer => "sanitizer",
            Self::Guard => "guard",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StaticRegistryPatternKind {
    SymbolEquals,
    SymbolContains,
    PathContains,
    TextContains,
}

impl StaticRegistryPatternKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SymbolEquals => "symbol_equals",
            Self::SymbolContains => "symbol_contains",
            Self::PathContains => "path_contains",
            Self::TextContains => "text_contains",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticRegistryEntry {
    pub id: &'static str,
    pub version: &'static str,
    pub language: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<&'static str>,
    pub kind: StaticRegistryKind,
    pub pattern_kind: StaticRegistryPatternKind,
    pub pattern: &'static str,
    pub cwe: &'static [&'static str],
    pub rationale: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticRegistryQuery<'a> {
    pub language: &'a str,
    pub framework: Option<&'a str>,
    pub path: Option<&'a str>,
    pub symbol: Option<&'a str>,
    pub text: Option<&'a str>,
}

impl<'a> StaticRegistryQuery<'a> {
    pub fn new(language: &'a str) -> Self {
        Self {
            language,
            framework: None,
            path: None,
            symbol: None,
            text: None,
        }
    }

    pub fn framework(mut self, framework: &'a str) -> Self {
        self.framework = Some(framework);
        self
    }

    pub fn path(mut self, path: &'a str) -> Self {
        self.path = Some(path);
        self
    }

    pub fn symbol(mut self, symbol: &'a str) -> Self {
        self.symbol = Some(symbol);
        self
    }

    pub fn text(mut self, text: &'a str) -> Self {
        self.text = Some(text);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticRegistryMatch {
    pub entry: &'static StaticRegistryEntry,
    pub static_proof_state: StaticProofState,
    pub vulnerability_proof: bool,
}

pub fn static_registry_version() -> &'static str {
    STATIC_REGISTRY_VERSION
}

pub fn default_static_registry() -> &'static [StaticRegistryEntry] {
    DEFAULT_STATIC_REGISTRY
}

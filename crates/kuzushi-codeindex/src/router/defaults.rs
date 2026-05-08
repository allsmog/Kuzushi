use super::{Backend, BackendCapability, Query};

pub(crate) const DEFAULTS: &[BackendCapability] = &[
    BackendCapability {
        query: Query::Definitions,
        primary: Backend::Clang,
        fallback: Some(Backend::Gtags),
        last_resort: Some(Backend::Joern),
    },
    BackendCapability {
        query: Query::References,
        primary: Backend::Clang,
        fallback: Some(Backend::Gtags),
        last_resort: Some(Backend::Joern),
    },
    BackendCapability {
        query: Query::SymbolsInFile,
        primary: Backend::Gtags,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::FilesMatching,
        primary: Backend::Gtags,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::Completion,
        primary: Backend::Gtags,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::CallersOfFunction,
        primary: Backend::Clang,
        fallback: Some(Backend::Joern),
        last_resort: Some(Backend::Gtags),
    },
    BackendCapability {
        query: Query::CalleesOfFunction,
        primary: Backend::Joern,
        fallback: Some(Backend::Clang),
        last_resort: Some(Backend::Gtags),
    },
    BackendCapability {
        query: Query::TaintPaths,
        primary: Backend::Joern,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::ReachingDef,
        primary: Backend::Joern,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::UnsafeBlocks,
        primary: Backend::Joern,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::FfiBoundaries,
        primary: Backend::Joern,
        fallback: Some(Backend::Clang),
        last_resort: None,
    },
    BackendCapability {
        query: Query::TypeAtPosition,
        primary: Backend::Clang,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::AstAtPosition,
        primary: Backend::Clang,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::MacroExpansion,
        primary: Backend::Clang,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::MethodAtPosition,
        primary: Backend::Joern,
        fallback: Some(Backend::Clang),
        last_resort: Some(Backend::Gtags),
    },
];

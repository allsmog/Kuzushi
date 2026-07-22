use super::{Backend, BackendCapability, Query};

pub(crate) const DEFAULTS: &[BackendCapability] = &[
    BackendCapability {
        query: Query::Definitions,
        primary: Backend::Clang,
        fallback: Some(Backend::Gtags),
        last_resort: Some(Backend::Cpg),
    },
    BackendCapability {
        query: Query::References,
        primary: Backend::Clang,
        fallback: Some(Backend::Gtags),
        last_resort: None,
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
        fallback: Some(Backend::Cpg),
        last_resort: Some(Backend::Gtags),
    },
    BackendCapability {
        query: Query::CalleesOfFunction,
        primary: Backend::Cpg,
        fallback: Some(Backend::Clang),
        last_resort: Some(Backend::Gtags),
    },
    BackendCapability {
        query: Query::TaintPaths,
        primary: Backend::Cpg,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::ReachingDef,
        primary: Backend::Cpg,
        fallback: None,
        last_resort: None,
    },
    // No cpg-rs equivalent yet: the facade methods refuse with guidance
    // (tree-sitter for unsafe blocks, cpg.callers_of for dynamic loads),
    // so these routes are placeholders that keep the query set total.
    BackendCapability {
        query: Query::UnsafeBlocks,
        primary: Backend::Cpg,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::FfiBoundaries,
        primary: Backend::Cpg,
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
    // Clang is exact (real ranges); the cpg-rs fallback is start-line
    // approximate (no method end lines in the graph).
    BackendCapability {
        query: Query::MethodAtPosition,
        primary: Backend::Clang,
        fallback: Some(Backend::Cpg),
        last_resort: Some(Backend::Gtags),
    },
];

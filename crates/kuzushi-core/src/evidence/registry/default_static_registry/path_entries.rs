use super::*;

pub(crate) const PATH_REGISTRY_ENTRIES: &[StaticRegistryEntry] = &[StaticRegistryEntry {
    id: "path.config-env",
    version: STATIC_REGISTRY_VERSION,
    language: "TypeScript",
    framework: None,
    kind: StaticRegistryKind::Source,
    pattern_kind: StaticRegistryPatternKind::PathContains,
    pattern: ".env",
    cwe: &["CWE-200"],
    rationale: "Environment files often contain sensitive configuration and should not be exposed.",
}];

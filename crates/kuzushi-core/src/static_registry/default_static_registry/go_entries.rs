use super::*;

pub(crate) const GO_REGISTRY_ENTRIES: &[StaticRegistryEntry] = &[
    StaticRegistryEntry {
        id: "go.source-http-query",
        version: STATIC_REGISTRY_VERSION,
        language: "Go",
        framework: None,
        kind: StaticRegistryKind::Source,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "r.URL.Query",
        cwe: &["CWE-20"],
        rationale: "net/http URL query values are externally controlled request input.",
    },
    StaticRegistryEntry {
        id: "go.sink-os-exec-command",
        version: STATIC_REGISTRY_VERSION,
        language: "Go",
        framework: None,
        kind: StaticRegistryKind::Sink,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "exec.Command",
        cwe: &["CWE-78"],
        rationale:
            "Command construction is security-sensitive when arguments include untrusted data.",
    },
    StaticRegistryEntry {
        id: "go.sanitizer-template-escape",
        version: STATIC_REGISTRY_VERSION,
        language: "Go",
        framework: None,
        kind: StaticRegistryKind::Sanitizer,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "template.HTMLEscapeString",
        cwe: &["CWE-79"],
        rationale: "HTML escaping can neutralize markup when used at the correct output boundary.",
    },
    StaticRegistryEntry {
        id: "go.guard-auth-middleware",
        version: STATIC_REGISTRY_VERSION,
        language: "Go",
        framework: None,
        kind: StaticRegistryKind::Guard,
        pattern_kind: StaticRegistryPatternKind::TextContains,
        pattern: "AuthMiddleware",
        cwe: &["CWE-862"],
        rationale: "Auth middleware can gate access to HTTP handlers.",
    },
];

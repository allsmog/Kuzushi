use super::FindingClass;

pub(super) fn class_from_keywords(text: &str) -> Option<FindingClass> {
    let text = text.to_ascii_lowercase();
    KEYWORD_CLASSES
        .iter()
        .find(|(needles, _)| needles.iter().any(|needle| text.contains(needle)))
        .map(|(_, class)| *class)
}

const KEYWORD_CLASSES: &[(&[&str], FindingClass)] = &[
    (
        &[
            "oob write",
            "out-of-bounds write",
            "heap overflow",
            "stack overflow",
            "buffer overflow",
        ],
        FindingClass::MemOobWrite,
    ),
    (
        &["oob read", "out-of-bounds read", "overread"],
        FindingClass::MemOobRead,
    ),
    (
        &["use-after-free", "use after free", "uaf"],
        FindingClass::MemUseAfterFree,
    ),
    (&["double free", "double-free"], FindingClass::MemDoubleFree),
    (&["uninitialized"], FindingClass::MemUninit),
    (
        &["integer overflow", "integer truncation", "int overflow"],
        FindingClass::IntOverflow,
    ),
    (
        &[
            "sql injection",
            "command injection",
            "xss",
            "code injection",
            "template injection",
        ],
        FindingClass::Injection,
    ),
    (
        &["path traversal", "directory traversal", "zip slip"],
        FindingClass::PathTraversal,
    ),
    (&["ssrf", "server-side request forgery"], FindingClass::Ssrf),
    (&["xxe", "xml external entity"], FindingClass::Xxe),
    (
        &["deserialization", "unsafe pickle", "unsafe yaml"],
        FindingClass::Deserialization,
    ),
    (
        &[
            "auth bypass",
            "authentication bypass",
            "missing authentication",
        ],
        FindingClass::AuthBypass,
    ),
    (
        &[
            "authorization",
            "idor",
            "missing authz",
            "privilege escalation",
        ],
        FindingClass::AuthzMissing,
    ),
    (
        &[
            "weak cipher",
            "weak hash",
            "hardcoded iv",
            "insecure random",
            "crypto",
        ],
        FindingClass::CryptoMisuse,
    ),
    (
        &[
            "hardcoded secret",
            "hardcoded credential",
            "hardcoded password",
            "api key",
        ],
        FindingClass::SecretExposure,
    ),
    (&["race condition", "toctou"], FindingClass::RaceCondition),
    (
        &["denial of service", "infinite loop", "resource exhaustion"],
        FindingClass::Dos,
    ),
    (
        &["information leak", "info leak", "information disclosure"],
        FindingClass::InfoLeak,
    ),
];

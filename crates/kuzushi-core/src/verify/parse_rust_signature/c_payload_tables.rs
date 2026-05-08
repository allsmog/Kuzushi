use super::*;

pub(in crate::verify) const C_SINGLE_ARG_PAYLOADS: &[(&[&str], &str)] = &[
    (
        &[
            "const uint8_t *",
            "const uint8_t*",
            "uint8_t const *",
            "uint8_t const*",
            "const char *",
            "const char*",
            "char const *",
            "char const*",
            "const void *",
            "const void*",
            "void const *",
            "void const*",
        ],
        "(const uint8_t *)data",
    ),
    (
        &[
            "uint8_t *",
            "uint8_t*",
            "char *",
            "char*",
            "void *",
            "void*",
        ],
        "(uint8_t *)data",
    ),
    (&["size_t"], "len"),
    (&["int"], "(int)len"),
    (&["unsigned", "unsigned int", "uint32_t"], "(uint32_t)len"),
    (&["long", "long long", "uint64_t"], "(uint64_t)len"),
];

pub(in crate::verify) const C_BUFFER_EXPRESSIONS: &[(&[&str], &str)] = &[
    (
        &[
            "const uint8_t *",
            "const uint8_t*",
            "uint8_t const *",
            "uint8_t const*",
        ],
        "(const uint8_t *)data",
    ),
    (
        &["const char *", "const char*", "char const *", "char const*"],
        "(const char *)data",
    ),
    (
        &["const void *", "const void*", "void const *", "void const*"],
        "(const void *)data",
    ),
    (&["uint8_t *", "uint8_t*"], "(uint8_t *)data"),
    (&["char *", "char*"], "(char *)data"),
    (&["void *", "void*"], "(void *)data"),
];

pub(in crate::verify) const C_LENGTH_EXPRESSIONS: &[(&[&str], &str)] = &[
    (&["size_t"], "len"),
    (&["int"], "(int)len"),
    (&["unsigned", "unsigned int", "uint32_t"], "(uint32_t)len"),
    (&["long", "long long", "uint64_t"], "(uint64_t)len"),
];

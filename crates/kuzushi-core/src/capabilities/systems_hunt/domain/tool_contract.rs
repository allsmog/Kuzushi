pub(crate) const SYSTEMS_INVARIANT_SYSTEM_PROMPT: &str = "Systems Hunt invariant extractor";

pub(crate) const SYSTEMS_TRIGGER_SYSTEM_PROMPT: &str = "Systems Hunt trigger synthesizer";

pub(crate) const SYSTEMS_HUNT_SYSTEM_PROMPT: &str = "Systems Hunt low-level vulnerability hunter";

pub(crate) const DEEP_SEMANTIC_CWE_SYSTEM_PROMPT: &str = "Deep Semantic CWE selector";

pub(crate) const DEEP_SEMANTIC_HUNT_SYSTEM_PROMPT: &str = "Deep Semantic Hunt vulnerability hunter";

pub(crate) const SYSTEMS_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx", "rs", "go", "zig",
];

pub(crate) const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".kuzushi",
    ".next",
    ".turbo",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
];

pub(crate) const NON_PRODUCTION_SYSTEMS_DIRS: &[&str] = &[
    "__tests__",
    "doc",
    "docs",
    "example",
    "examples",
    "fixtures",
    "test",
    "tests",
];

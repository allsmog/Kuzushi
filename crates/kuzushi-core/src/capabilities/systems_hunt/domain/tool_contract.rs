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

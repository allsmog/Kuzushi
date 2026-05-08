pub(in crate::scan) struct CodeqlMarkerRule {
    pub(in crate::scan) language: &'static str,
    pub(in crate::scan) markers: &'static [&'static str],
}

pub(in crate::scan) const CODEQL_ALL_MARKER_RULES: &[CodeqlMarkerRule] = &[
    CodeqlMarkerRule {
        language: "javascript",
        markers: &["package.json"],
    },
    CodeqlMarkerRule {
        language: "go",
        markers: &["go.mod"],
    },
    CodeqlMarkerRule {
        language: "java",
        markers: &["pom.xml", "build.gradle", "build.gradle.kts"],
    },
    CodeqlMarkerRule {
        language: "python",
        markers: &["requirements.txt", "pyproject.toml", "setup.py"],
    },
    CodeqlMarkerRule {
        language: "rust",
        markers: &["Cargo.toml"],
    },
    CodeqlMarkerRule {
        language: "ruby",
        markers: &["Gemfile"],
    },
];

pub(in crate::scan) const CODEQL_HEURISTIC_MARKER_RULES: &[CodeqlMarkerRule] = &[
    CodeqlMarkerRule {
        language: "javascript",
        markers: &["package.json"],
    },
    CodeqlMarkerRule {
        language: "go",
        markers: &["go.mod"],
    },
    CodeqlMarkerRule {
        language: "java",
        markers: &[
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "gradlew",
            "mvnw",
        ],
    },
    CodeqlMarkerRule {
        language: "python",
        markers: &["requirements.txt", "pyproject.toml", "setup.py"],
    },
    CodeqlMarkerRule {
        language: "rust",
        markers: &["Cargo.toml"],
    },
    CodeqlMarkerRule {
        language: "ruby",
        markers: &["Gemfile"],
    },
];

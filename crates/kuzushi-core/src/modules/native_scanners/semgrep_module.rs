use super::*;

pub(in crate::modules) fn semgrep_module() -> BuiltinModule {
    builtin_module(
        "semgrep",
        "Semgrep Scan",
        ModuleKind::Defense,
        "Native SAST path using semgrep JSON output.",
        vec![tool_with_options(
            "semgrep:scan",
            "Run semgrep and persist normalized findings.",
            vec![
                target_option(),
                binary_option("Semgrep binary path."),
                opt("config", OptionType::String, "Semgrep config name or path.")
                    .aliases(&["configFlag", "config_flag"])
                    .default(json!("auto")),
            ],
        )],
        vec![dag("semgrep:scan", "findings", &["context:build"])],
    )
}

pub(in crate::modules) fn codeql_module() -> BuiltinModule {
    builtin_module(
        "codeql",
        "CodeQL",
        ModuleKind::Defense,
        "GitHub's taint-query semantic analyzer: deeper than pattern scanners but slower.",
        vec![tool_with_options(
            "codeql:scan",
            "Run CodeQL and normalize semantic findings.",
            vec![
                target_option(),
                binary_option("CodeQL binary path."),
                opt("dbPath", OptionType::Path, "Existing CodeQL database path.")
                    .aliases(&["db_path"])
                    .advanced(),
                opt("language", OptionType::Enum, "CodeQL language to analyze.").choices(&[
                    "javascript",
                    "python",
                    "csharp",
                    "c#",
                    "java",
                    "go",
                    "cpp",
                    "c++",
                    "c-cpp",
                    "swift",
                    "ruby",
                    "rust",
                    "typescript",
                ]),
                opt("suite", OptionType::String, "CodeQL query suite.").advanced(),
                opt("threads", OptionType::Int, "CodeQL worker thread count.").advanced(),
                opt("ram", OptionType::Int, "CodeQL RAM budget in MB.").advanced(),
                opt(
                    "multiLanguage",
                    OptionType::Bool,
                    "Analyze all detected CodeQL languages.",
                )
                .aliases(&["multi_language"])
                .default(json!(false)),
            ],
        )],
        vec![dag("codeql:scan", "findings", &["context:build"])],
    )
}

pub(in crate::modules) fn iac_scan_module() -> BuiltinModule {
    builtin_module(
        "iac-scan",
        "IaC Scan",
        ModuleKind::Defense,
        "Scan IaC manifests for security misconfigurations.",
        vec![tool_with_options(
            "iac-scan:scan",
            "Scan Terraform, Kubernetes, and related IaC manifests.",
            vec![
                target_option(),
                opt("kind", OptionType::Enum, "IaC file family to scan.")
                    .choices(&[
                        "all",
                        "dockerfile",
                        "docker",
                        "github-actions",
                        "github_actions",
                        "actions",
                        "terraform",
                        "tf",
                    ])
                    .default(json!("all")),
                opt(
                    "maxFileBytes",
                    OptionType::Int,
                    "Maximum file size to scan.",
                )
                .aliases(&["max_file_bytes"])
                .default(json!(524288)),
            ],
        )],
        vec![dag("iac-scan:scan", "findings", &["context:build"])],
    )
}

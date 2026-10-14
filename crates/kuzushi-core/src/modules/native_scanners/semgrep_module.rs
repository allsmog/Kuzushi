use super::*;

pub(in crate::modules) fn semgrep_module() -> BuiltinModule {
    builtin_module(
        "semgrep",
        "Semgrep Scan",
        ModuleKind::Defense,
        "Native SAST path using semgrep JSON output.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            ),
            vec![tool_with_options(
                "semgrep:scan",
                "Run semgrep and persist normalized findings.",
                semgrep_options(),
            )],
        ),
        vec![dag("semgrep:scan", "findings", &["context:build"])],
    )
}

fn semgrep_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        binary_option("Semgrep binary path."),
        scan_mode_option(),
        whitebox_static_option(),
        static_proof_state_option(),
        opt("config", OptionType::String, "Semgrep config name or path.")
            .aliases(&["configFlag", "config_flag"])
            .default(json!(crate::scan::DEFAULT_SEMGREP_CONFIG)),
    ]
}

pub(in crate::modules) fn codeql_module() -> BuiltinModule {
    builtin_module(
        "codeql",
        "CodeQL",
        ModuleKind::Defense,
        "GitHub's taint-query semantic analyzer: deeper than pattern scanners but slower.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            ),
            vec![tool_with_options(
                "codeql:scan",
                "Run CodeQL and normalize semantic findings.",
                codeql_options(),
            )],
        ),
        vec![dag("codeql:scan", "findings", &["context:build"])],
    )
}

fn codeql_options() -> Vec<OptionSpec> {
    let mut options = vec![
        target_option(),
        binary_option("CodeQL binary path."),
        scan_mode_option(),
        whitebox_static_option(),
        static_proof_state_option(),
        opt("dbPath", OptionType::Path, "Existing CodeQL database path.")
            .aliases(&["db_path"])
            .workspace_read()
            .advanced(),
        codeql_language_option(),
        opt(
            "buildMode",
            OptionType::Enum,
            "Deprecated compatibility input. Scans consume an existing database; pass the build mode to codeql:create-db when creating it.",
        )
            .aliases(&["build_mode"])
            .choices(&["default", "autobuild", "none"])
            .advanced(),
        opt("suite", OptionType::String, "CodeQL query suite.").advanced(),
        opt("threads", OptionType::Int, "CodeQL worker thread count.").advanced(),
        opt("ram", OptionType::Int, "CodeQL RAM budget in MB.").advanced(),
        opt(
            "timeoutMs",
            OptionType::Int,
            "Per-command CodeQL resolve/analyze deadline in milliseconds. A deadline kills and reaps the complete CodeQL process tree.",
        )
        .aliases(&["timeout_ms"])
        .default(json!(
            crate::scan::engines::codeql::DEFAULT_CODEQL_SCAN_TIMEOUT_MS
        ))
        .advanced(),
    ];
    options.push(codeql_multi_language_option());
    options
}

fn scan_mode_option() -> OptionSpec {
    opt("mode", OptionType::Enum, "Analysis mode or preset.")
        .aliases(&["preset"])
        .choices(&["standard", "whitebox-static"])
        .default(json!("standard"))
        .advanced()
}

fn whitebox_static_option() -> OptionSpec {
    opt(
        "whiteboxStatic",
        OptionType::Json,
        "Enable whitebox-static mode.",
    )
    .aliases(&["whitebox_static"])
    .advanced()
}

fn static_proof_state_option() -> OptionSpec {
    opt(
        "staticProofState",
        OptionType::String,
        "Default static proof state for whitebox-static findings.",
    )
    .aliases(&["static_proof_state"])
    .advanced()
}

fn codeql_language_option() -> OptionSpec {
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
    ])
}

fn codeql_multi_language_option() -> OptionSpec {
    opt(
        "multiLanguage",
        OptionType::Bool,
        "Analyze all detected CodeQL languages.",
    )
    .aliases(&["multi_language"])
    .default(json!(false))
}

pub(in crate::modules) fn iac_scan_module() -> BuiltinModule {
    builtin_module(
        "iac-scan",
        "IaC Scan",
        ModuleKind::Defense,
        "Scan IaC manifests for security misconfigurations.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            ),
            vec![tool_with_options(
                "iac-scan:scan",
                "Scan Terraform, Kubernetes, and related IaC manifests.",
                iac_scan_options(),
            )],
        ),
        vec![dag("iac-scan:scan", "findings", &["context:build"])],
    )
}

fn iac_scan_options() -> Vec<OptionSpec> {
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
    ]
}

pub(in crate::modules) fn cargo_audit_module() -> BuiltinModule {
    builtin_module(
        "cargo-audit",
        "Cargo Audit",
        ModuleKind::Defense,
        "Run cargo-audit against Rust lockfiles and persist advisory findings.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            ),
            vec![tool_with_options(
                "cargo-audit:scan",
                "Run cargo audit and persist normalized findings.",
                vec![target_option()],
            )],
        ),
        vec![dag("cargo-audit:scan", "findings", &["context:build"])],
    )
}

pub(in crate::modules) fn govulncheck_module() -> BuiltinModule {
    builtin_module(
        "govulncheck",
        "Govulncheck",
        ModuleKind::Defense,
        "Run govulncheck against Go packages and persist reachable vulnerability findings.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            ),
            vec![tool_with_options(
                "govulncheck:scan",
                "Run govulncheck and persist normalized Go vulnerability findings.",
                vec![target_option()],
            )],
        ),
        vec![dag("govulncheck:scan", "findings", &["context:build"])],
    )
}

pub(in crate::modules) fn license_scan_module() -> BuiltinModule {
    builtin_module(
        "license-scan",
        "License Scan",
        ModuleKind::Defense,
        "Scan package manifests for missing or copyleft license declarations.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            ),
            vec![tool_with_options(
                "license-scan:scan",
                "Scan package manifests for license-risk findings.",
                vec![
                    target_option(),
                    opt(
                        "requireSourceSpdxHeaders",
                        OptionType::Bool,
                        "Require source files to carry SPDX license headers.",
                    )
                    .aliases(&[
                        "require_source_spdx_headers",
                        "requireSpdxHeaders",
                        "require_spdx_headers",
                    ])
                    .default(json!(false)),
                ],
            )],
        ),
        vec![dag("license-scan:scan", "findings", &["context:build"])],
    )
}

pub(in crate::modules) fn sbom_scan_module() -> BuiltinModule {
    builtin_module(
        "sbom-scan",
        "SBOM Scan",
        ModuleKind::Governance,
        "Extract a deterministic dependency inventory from package manifests.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            ),
            vec![tool_with_options(
                "sbom-scan:scan",
                "Inventory declared and resolved dependencies. This produces no vulnerability findings or phase completion.",
                vec![target_option()],
            ).without_phase_result()],
        ),
        vec![dag("sbom-scan:scan", "artifact", &["context:build"])],
    )
}

pub(in crate::modules) fn exploit_chain_module() -> BuiltinModule {
    builtin_module(
        "exploit-chain",
        "Exploit Chain Scan",
        ModuleKind::Defense,
        "LLM-driven analyzer that connects vulnerability primitives into likely exploit paths and PoC guidance.",
        tools_with_policy(workspace_policy(ToolPhase::Scan, RuntimeRequirement::Always, FindingStoreRequirement::Required), vec![tool_with_options(
            "exploit-chain:scan",
            "Scan source for chained exploitability signals and synthesize PoC shapes with the configured agent runtime.",
            vec![
                target_option(),
                model_option(),
                opt(
                    "maxEvidence",
                    OptionType::Int,
                    "Maximum source excerpts sent to LLM evidence extraction.",
                )
                .aliases(&["max_evidence"])
                .default(json!(140))
                .advanced(),
            ],
        )]),
        vec![dag("exploit-chain:scan", "findings", &["context:build"])],
    )
}
